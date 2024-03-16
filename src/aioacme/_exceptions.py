from aioacme._models import Error


class AcmeError(Exception):
    def __init__(self, error: Error) -> None:
        self.error = error
        super().__init__(str(error))
