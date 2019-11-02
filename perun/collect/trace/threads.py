""" Module containing various thread related features such as timeout or heartbeat timers.
"""

import sys
from threading import Thread, Event

from perun.collect.trace.watchdog import WD


class NonBlockingTee(Thread):
    """ The NonBlockingTee imitates the 'tee' utility and routes the stream output to
    a terminal and file.

    However, the interactivity of the output (i.e. if the terminal output as well as the file
    updates are real-time) depends heavily on the use of buffers in the application that is
    generating the output.

    :ivar Stream _stream: stream object that is being read
    :ivar str file: the name of the file to store the stream output to
    """
    def __init__(self, stream, file):
        """ Construct the NonBlockingTee object

        :param Stream stream: stream object that can be read
        :param str file: the name of the file to store the stream output to
        """
        super().__init__()
        self._stream = stream
        self._file = file
        # Start the thread immediately
        self.start()

    def run(self):
        """ The thread loop which blocks until new output from the stream is available.
        """
        WD.debug("NonBlockingTee thread starting, output stored in '{}'".format(self._file))
        with open(self._file, 'wb') as tee_file:
            try:
                # Wait for a next line from the stream
                for line in self._stream:
                    if line:
                        sys.stdout.buffer.write(line)
                        tee_file.write(line)
                    else:
                        # No more output lines
                        break
            except ValueError:
                # The stream was closed, stop the thread
                pass
            finally:
                # Flush all the buffers before terminating the thread
                sys.stdout.buffer.flush()
                tee_file.flush()
                WD.debug("NonBlockingTee thread terminating")


class HeartbeatThread(Thread):
    """ The HeartbeatThread allows to periodically perform given action as long as the timer
    is not disabled. This is used to e.g. inform the user about the progress of time-intensive
    operations.

    The thread is intended to be used as a context manager.

    :ivar Event _stop_event: the threading.Event object used to interrupt the sleeping thread
    :ivar float _timer: the interval of the periodical action
    :ivar function _callback: the action to perform periodically
    :ivar tuple callback_args: the arguments of the action function
    """
    def __init__(self, timer, callback, callback_args):
        """ Creates the HeartbeatThread object

        :param float timer: the interval of the periodical action
        :param function callback: the action to perform periodically
        :param tuple callback_args: the arguments of the action function
        """
        super().__init__()
        self._stop_event = Event()
        self._timer = timer
        self._callback = callback
        self._callback_args = callback_args

    def run(self):
        """ The thread loop that waits for a stop event to happen. After each _timer amount
        of time, the waiting is interrupted and the action is invoked.
        """
        WD.debug("HeartbeatThread starting, action will be performed every {}s".format(self._timer))
        # Repeat the wait as long as the stop event is not set
        while not self._stop_event.is_set():
            # Wait the _timer seconds or until the stop event is set
            if self._stop_event.wait(self._timer):
                # The sleep was interrupted by the stop_event, terminated the thread
                break
            # The sleep was interrupted by a wait timeout, perform the action
            self._callback(*self._callback_args)
        WD.debug("HeartbeatThread stop_event detected, terminating the thread")

    def __enter__(self):
        """ The context manager entry sentinel, starts the thread loop.

        :return HeartbeatThread: the thread object
        """
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """ The context manager exit sentinel, sets the stop_event flag so that the thread loop
        terminates.

        :param type exc_type: the type of the exception
        :param exception exc_val: the value of the exception
        :param traceback exc_tb: the exception traceback
        """
        self._stop_event.set()


class TimeoutThread(Thread):
    """ The TimeoutThread starts a timer that waits for a specified amount of time, after which
    a flag that indicates the reached timeout is set.

    The thread is intended to be used as a context manager.

    :ivar Event timeout_event: the threading.Event that represents the timer
    :ivar float _timer: the time to wait until a timeout is reached
    """
    def __init__(self, timer):
        """ Creates the TimeoutThread object

        :param float timer: the time to wait until a timeout is reached
        """
        super().__init__()
        self.timeout_event = Event()
        self._timer = timer

    def run(self):
        """ The thread loop that waits for the timeout to be reached.
        """
        WD.debug("TimeoutThread started, waiting for {}s".format(self._timer))
        if self.timeout_event.wait(self._timer):
            WD.debug("TimeoutThread interrupted before reaching the timeout")
            return
        # Set the event so that the main thread can check, that the timeout has been reached
        self.timeout_event.set()
        WD.debug("Timeout reached")

    def reached(self):
        """ Checks if the timeout has already been reached.

        :return bool: true if the timeout has been reached
        """
        return self.timeout_event.is_set()

    def __enter__(self):
        """ The context manager entry sentinel, starts the thread loop.

        :return TimeoutThread: the thread object
        """
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """ The context manager exit sentinel, stops the timer if it is still running.

        :param type exc_type: the type of the exception
        :param exception exc_val: the value of the exception
        :param traceback exc_tb: the exception traceback
        """
        # The event might be already set, if the timer went off
        # Or it might not, if the main thread has been interrupted by a signal etc.
        if not self.timeout_event.is_set():
            self.timeout_event.set()