"""Quick checks for the logic that decides who gets warned. Run:  python tests/test_core.py"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import brands, sandbox
sandbox.ALLOW_LOCAL = False

def t(name, cond):
    print(("PASS " if cond else "FAIL ") + name)
    return cond

ok = True
# trust: matched on registered domain, not substrings
ok &= t("official PayPal is trusted",              bool(brands.trusted("https://www.paypal.com/signin")))
ok &= t("official subdomain is trusted",           bool(brands.trusted("https://netbanking.hdfcbank.com/netbanking/")))
ok &= t("college domain (ac.in) is trusted",       bool(brands.trusted("https://www.kct.ac.in/")))
ok &= t("paypal.com.evil.ru is NOT trusted",       not brands.trusted("http://paypal.com.evil.ru/login"))
ok &= t("notpaypal.com is NOT trusted",            not brands.trusted("http://notpaypal.com/"))
# impersonation
ok &= t("paypa1 look-alike detected",              brands.impersonation("http://paypa1-secure-login.com/")[0] == "PayPal")
ok &= t("amaz0n look-alike detected",              brands.impersonation("http://amaz0n-order-confirm.cf/")[0] == "Amazon")
ok &= t("sbi token detected",                      brands.impersonation("https://sbi-kyc-update-online.in/")[0] == "SBI")
ok &= t("paypal in subdomain of evil host",        brands.impersonation("http://secure.paypal.com.confirm-id.ru/webscr")[0] == "PayPal")
ok &= t("real PayPal is not impersonation",        brands.impersonation("https://www.paypal.com/signin") is None)
ok &= t("unrelated site is not impersonation",     brands.impersonation("https://www.thehindu.com/news/") is None)
ok &= t("IP address kept whole",                   brands.registered_domain("203.0.113.45") == "203.0.113.45")
ok &= t("co.in registered domain handled",         brands.registered_domain("netbanking.sbi.co.in") == "sbi.co.in")
# sandbox safety: must refuse internal targets and non-web schemes
for u in ("http://127.0.0.1/", "http://169.254.169.254/latest/meta-data/", "http://10.0.0.5/", "http://[::1]/", "file:///etc/passwd", "ftp://example.com/"):
    r = sandbox.inspect(u)
    ok &= t(f"inspector refuses {u}", r.get("fetched") is False)
print("\nALL PASSED" if ok else "\nSOME CHECKS FAILED")
sys.exit(0 if ok else 1)
