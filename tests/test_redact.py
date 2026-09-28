import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plugins" / "ops-toolkit" / "skills" / "log-detective" / "scripts"))
from redact import Redactor  # noqa: E402


def red(text):
    return Redactor().redact(text)


class RedactSecrets(unittest.TestCase):
    def test_jwt(self):
        t = "Authorization failed for token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        self.assertNotIn("eyJhbGci", red(t))

    def test_bearer_header(self):
        self.assertNotIn("abcdef1234567890XYZ", red("Authorization: Bearer abcdef1234567890XYZ"))

    def test_storage_connection_string(self):
        t = "DefaultEndpointsProtocol=https;AccountName=storders;AccountKey=Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZg==;EndpointSuffix=core.windows.net"
        out = red(t)
        self.assertNotIn("Zm9vYmFy", out)
        self.assertIn("AccountName=storders", out)  # non-secret context kept for diagnosis

    def test_sql_connection_password(self):
        out = red("Server=tcp:sql-orders.database.windows.net;User ID=app;Password=S3cr3t!Pass;Encrypt=True")
        self.assertNotIn("S3cr3t!Pass", out)
        self.assertIn("sql-orders.database.windows.net", out)

    def test_sas_signature(self):
        out = red("GET https://st.blob.core.windows.net/c/f.csv?sv=2022-11-02&sig=AbCdEf1234567890%2BqRsTuV%3D&se=2026")
        self.assertNotIn("AbCdEf1234567890", out)

    def test_aws_keys(self):
        out = red("aws_access_key_id=AKIAIOSFODNN7EXAMPLE aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", out)
        self.assertNotIn("wJalrXUtnFEMI", out)

    def test_github_token_and_generic_secret(self):
        out = red('ghp_FAKE0000000000000000000000TEST client_secret="q8Q~abcdEFGH12345.xyz"')
        self.assertNotIn("ghp_FAKE", out)
        self.assertNotIn("q8Q~abcd", out)

    def test_private_key_block(self):
        out = red("-----BEGIN RSA PRIVATE KEY-----\nMIIEow\nabc\n-----END RSA PRIVATE KEY-----")
        self.assertNotIn("MIIEow", out)


class RedactEscapedAndKnownTokens(unittest.TestCase):
    """Regression: an API key inside an escaped JSON request body (Azure Activity Log) leaked in 1.1 testing."""

    def test_escaped_json_in_activity_log_body(self):
        body = r'"requestbody": "{\"properties\": {\"PaymentGateway__ApiKey\": \"abc123SECRETvalue\", \"PaymentGateway__BaseUrl\": \"https://paymentgw-v2.internal\"}}"'
        out = red(body)
        self.assertNotIn("abc123SECRETvalue", out)
        self.assertIn("paymentgw-v2.internal", out)  # the diagnostic value stays

    def test_known_token_formats_whatever_the_key(self):
        stripe = "sk" + "_live_" + "9f8e7d6c5b4a3210fedc"
        slack = "xoxb" + "-1234567890-abcdefghij"
        google = "AIza" + "Sy" + "A" * 33
        for secret in (stripe, slack, google):
            with self.subTest(secret[:6]):
                self.assertNotIn(secret, red(f"setting value={secret} end"))
                self.assertNotIn(secret, red(f"note: {secret}"))

    def test_more_key_names(self):
        for line, secret in (("SubscriptionKey=abcdef123456", "abcdef123456"),
                             ("Ocp-Apim-Subscription-Key: 0123456789abcdef", "0123456789abcdef"),
                             ('"primaryKey": "Zm9vYmFyYmF6cXV4"', "Zm9vYmFyYmF6cXV4"),
                             ("DB_PWD=Sup3rS3cret", "Sup3rS3cret")):
            with self.subTest(line):
                self.assertNotIn(secret, red(line))

    def test_look_alikes_left_alone(self):
        for line in ("tokens_used=123456", "MaxTokenCount: 4096", "keyboard: us",
                     "PaymentGateway__BaseUrl: https://paymentgw-v2.internal", "sort_key=created_at"):
            with self.subTest(line):
                self.assertEqual(red(line), line)


class RedactPersonalData(unittest.TestCase):
    def test_consistent_email_pseudonyms(self):
        out = red("login failed user=jane.doe@contoso.com; retry by jane.doe@contoso.com; also bob@fabrikam.io")
        self.assertEqual(out.count("<email-1>"), 2)
        self.assertIn("<email-2>", out)
        self.assertNotIn("contoso.com", out)

    def test_ipv4_but_not_versions_or_loopback(self):
        out = red("client 203.0.113.45 -> 127.0.0.1 using lib 1.2.3 build 10.0.19045")
        self.assertIn("<ipv4-1>", out)
        self.assertIn("127.0.0.1", out)
        self.assertIn("1.2.3", out)

    def test_card_numbers_luhn_only(self):
        out = red("card 4111 1111 1111 1111 order 1234567890123456")
        self.assertIn("<card-1>", out)
        self.assertIn("1234567890123456", out)  # fails Luhn -> an order id, kept

    def test_phone_international_only(self):
        out = red("call +44 20 7946 0958 about order 20260927 at 14:05")
        self.assertIn("<phone-1>", out)
        self.assertIn("20260927", out)

    def test_diagnostic_content_survives(self):
        line = ("2026-09-27T10:04:11Z ERROR OrderService.PlaceOrder System.NullReferenceException: "
                "Object reference not set at Orders.Api.Services.OrderService.ApplyDiscount(Order o) line 142 "
                "operation_Id=4bf92f3577b34da6a3ce929d0e0e4736 resultCode=500 duration=1532ms")
        self.assertEqual(red(line), line)

    def test_counts(self):
        r = Redactor()
        r.redact("a@b.com c@d.com a@b.com 10.1.2.3")
        self.assertEqual(r.counts["email"], 3)
        self.assertEqual(len(r.maps["email"]), 2)
        self.assertEqual(r.counts["ipv4"], 1)


if __name__ == "__main__":
    unittest.main()
