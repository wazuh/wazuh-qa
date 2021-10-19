import threading


class ThreadExecutor(threading.Thread):
    """Class which allows us to upload the thread exception to the parent process.

    This is useful to cause the pytest test to fail in the event of an exception or failure in any of the threads.

    Args:
        function (callable): Function to run in the thread.
        parameters (dict): Function parameters. Used as kwargs in the callable function.

    Attributes:
        function (callable): Function to run in the thread.
        parameters (dict): Function parameters. Used as kwargs in the callable function.
        exception (Exception): Thread exception in case it has occurred.
    """
    def __init__(self, function, parameters={}):
        super().__init__()
        self.function = function
        self.exception = None
        self.parameters = parameters
        self._return = None


    def _run(self):
        """Run the target function with its parameters in the thread"""
        self._return = self.function(**self.parameters)


    def run(self):
        """Overwrite run function of threading Thread module.

        Launch the target function and catch the exception in case it occurs.
        """
        self.exc = None
        try:
            self._run()
        except Exception as e:
            self.exception = e

    def join(self):
        """Overwrite join function of threading Thread module.

        Raises the exception to the parent in case it was raised when executing the target function.

        Raises:
            Exception: Target function exception if ocurrs
        """
        super(ThreadExecutor, self).join()
        if self.exception:
            raise self.exception

        return self._return
