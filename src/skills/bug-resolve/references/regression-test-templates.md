# Regression test templates

Minimal failing-test templates per stack. Always match the project's existing conventions first
(framework, folder, naming, fixtures, assertion style): these templates are the fallback when the
project gives you nothing to copy.

## Naming: name the behaviour, not the bug

A good name says what should happen, for which input, so the test still makes sense after the ticket
is closed.

| Good | Bad |
|---|---|
| `test_missing_currency_defaults_to_eur` | `test_bug_1234`, `test_fix`, `test_currency2` |
| `Total_GuestOrderWithoutDiscount_ReturnsFullPrice` | `TotalTest`, `NullRefFix` |
| `returns a generic greeting for a guest without a name` | `works`, `regression` |
| `TestParseQuantity_EmptyString_ReturnsZero` | `TestBug` |

Pattern: `<unit>_<condition>_<expected result>` (C#, Java, Go) or a sentence (pytest function names,
Jest/Vitest `it(...)` strings). Put the ticket number in a comment or the commit message, not the name.

## The proof: fail before, pass after

1. Write the test. Do not touch production code yet.
2. Run **only the new test** and save the output. It must fail **for the reason in the bug report**
   (same exception or same wrong value), not because of a typo, import error or compile error.
3. Make the fix. Run the new test again and save the output: it must pass.
4. Run the relevant suite and save the summary.
5. Give the three outputs to `fix_report.py` (`--before`, `--after`, `--suite`); it refuses to call
   the fix proven if the outputs do not show fail, then pass.

If the fix is already written, prove it after the fact by temporarily reverting just the fix files:
`git stash push -- <fixed files>`, run the new test (fails), `git stash pop`, run it again (passes).

Capture output with `2>&1 | tee before.txt` (bash) or `*> before.txt` (PowerShell).

---

## Python: pytest

```python
# tests/test_pricing.py
from shop.pricing import price_in_currency


def test_missing_currency_defaults_to_eur():
    # smallest synthetic input that triggers the bug
    market = {"rate": 1}

    amount, currency = price_in_currency(market, 10)

    assert currency == "EUR"
    assert amount == 10
```

Boundary variants in one test:

```python
import pytest


@pytest.mark.parametrize("market", [{}, {"currency": None}, {"currency": ""}])
def test_markets_without_a_usable_currency_default_to_eur(market):
    assert price_in_currency(market, 10)[1] == "EUR"
```

Expected-exception form: `with pytest.raises(ValueError, match="currency"):`.

Run one test: `python -m pytest tests/test_pricing.py::test_missing_currency_defaults_to_eur -q`
Fails before with `KeyError: 'currency'` and `1 failed`; passes after with `1 passed`.

---

## C#: xUnit

```csharp
using Xunit;

public class OrderServiceTests
{
    [Fact]
    public void Total_GuestOrderWithoutDiscount_ReturnsFullPrice()
    {
        var order = new Order { Quantity = 2, Discount = null };
        var sut = new OrderService();

        var total = sut.Total(order, 10m);

        Assert.Equal(20m, total);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public void Total_AnyQuantityWithoutDiscount_DoesNotThrow(int quantity)
    {
        var order = new Order { Quantity = quantity, Discount = null };

        var ex = Record.Exception(() => new OrderService().Total(order, 10m));

        Assert.Null(ex);
    }
}
```

## C#: NUnit

```csharp
using NUnit.Framework;

[TestFixture]
public class OrderServiceTests
{
    [Test]
    public void Total_GuestOrderWithoutDiscount_ReturnsFullPrice()
    {
        var order = new Order { Quantity = 2, Discount = null };

        var total = new OrderService().Total(order, 10m);

        Assert.That(total, Is.EqualTo(20m));
    }
}
```

## C#: MSTest

```csharp
using Microsoft.VisualStudio.TestTools.UnitTesting;

[TestClass]
public class OrderServiceTests
{
    [TestMethod]
    public void Total_GuestOrderWithoutDiscount_ReturnsFullPrice()
    {
        var order = new Order { Quantity = 2, Discount = null };

        var total = new OrderService().Total(order, 10m);

        Assert.AreEqual(20m, total);
    }
}
```

Run one test (any of the three):
`dotnet test --filter "FullyQualifiedName~OrderServiceTests.Total_GuestOrderWithoutDiscount_ReturnsFullPrice"`
Fails before with `System.InvalidOperationException : Nullable object must have a value.` and
`Failed!  - Failed: 1`; passes after with `Passed!  - Failed: 0`.

---

## TypeScript / JavaScript: Jest

```ts
// src/web/user.test.ts
import { greet } from "./user";

describe("greet", () => {
  it("returns a generic greeting for a guest without a name", () => {
    expect(greet(undefined)).toBe("Hello, guest");
  });

  it.each([{}, { name: "" }])("treats %p as a guest", (user) => {
    expect(greet(user)).toBe("Hello, guest");
  });
});
```

Run one test: `npx jest src/web/user.test.ts -t "guest without a name"`

## TypeScript / JavaScript: Vitest

Same body; import the globals explicitly unless `globals: true` is configured:

```ts
import { describe, it, expect } from "vitest";
import { greet } from "./user";

describe("greet", () => {
  it("returns a generic greeting for a guest without a name", () => {
    expect(greet(undefined)).toBe("Hello, guest");
  });
});
```

Run one test: `npx vitest run src/web/user.test.ts -t "guest without a name"`
Fails before with `TypeError: Cannot read properties of undefined` and `1 failed`; passes after with
`1 passed`.

---

## Java: JUnit 5

```java
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class UserServiceTest {

    @Test
    void nickname_whenUserHasNone_returnsEmptyInsteadOfThrowing() {
        UserService service = new UserService(new InMemoryUserRepository());

        assertEquals(Optional.empty(), service.nickname("u-1"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", " ", "unknown-id"})
    void nickname_forBlankOrUnknownIds_returnsEmpty(String id) {
        UserService service = new UserService(new InMemoryUserRepository());

        assertEquals(Optional.empty(), service.nickname(id));
    }
}
```

Other assertions: `assertThrows(NotFoundException.class, () -> ...)`, `assertDoesNotThrow(() -> ...)`.

Run one test: `mvn -Dtest=UserServiceTest#nickname_whenUserHasNone_returnsEmptyInsteadOfThrowing test`
or `./gradlew test --tests "UserServiceTest.nickname_whenUserHasNone*"`.
Fails before with `java.util.NoSuchElementException: No value present` and
`Tests run: 1, Failures: 0, Errors: 1`; passes after with `Tests run: 1, Failures: 0, Errors: 0`.

---

## Go: testing

```go
// qty/parse_test.go
package qty

import "testing"

func TestParseQuantity_EmptyString_ReturnsZero(t *testing.T) {
	got, err := ParseQuantity("")
	if err != nil {
		t.Fatalf("ParseQuantity(%q) error = %v, want nil", "", err)
	}
	if got != 0 {
		t.Errorf("ParseQuantity(%q) = %d, want 0", "", got)
	}
}

func TestParseQuantity_Boundaries(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want int
	}{
		{"empty", "", 0},
		{"spaces", "  ", 0},
		{"leading zero", "08", 8},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseQuantity(tt.in)
			if err != nil || got != tt.want {
				t.Errorf("ParseQuantity(%q) = %d, %v; want %d, nil", tt.in, got, err, tt.want)
			}
		})
	}
}
```

Run one test: `go test ./qty -run '^TestParseQuantity_EmptyString_ReturnsZero$' -v`
Fails before with `--- FAIL:` and `FAIL`; passes after with `--- PASS:` and `ok`.

---

## When a unit test cannot reproduce it

Timing, concurrency, infrastructure or data-volume bugs sometimes need an integration test. Write the
narrowest one possible (one real dependency, not the whole system), say in the report why a unit test
was not enough, and still show fail before / pass after. If nothing reproduces it, say so plainly
instead of shipping an unproven fix.
