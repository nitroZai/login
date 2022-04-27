

# In general used to reset the passwords, Can be used for activation of accounts as well
from django.contrib.auth.tokens import PasswordResetTokenGenerator

from six import text_type


class TokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp) -> str:
        return (
            text_type(user.pk) + text_type(timestamp)
            )

generate_token = TokenGenerator()