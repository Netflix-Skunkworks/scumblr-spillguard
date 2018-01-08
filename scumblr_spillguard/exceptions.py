class GeneralFailure(Exception):
    pass


class AuthenticationError(GeneralFailure):
    pass


class AuthorizationError(GeneralFailure):
    pass


class ThrottledError(GeneralFailure):
    pass