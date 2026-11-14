"""Standard API error type: rendered as {"error": code, "message": text}."""


class ApiError(Exception):
    def __init__(self, status: int, error: str, message: str):
        super().__init__(message)
        self.status, self.error, self.message = status, error, message
