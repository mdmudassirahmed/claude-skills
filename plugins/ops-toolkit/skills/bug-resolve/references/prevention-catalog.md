# Prevention catalog

After a bug is fixed and proven, propose **one** guardrail that stops the same class of bug coming back.
Pick the cheapest one the project will actually keep: a compiler/type-checker setting beats a linter
rule, a linter rule beats a code-review checklist item, and a targeted test beats nothing.

Rules for using this catalog:

- Propose, don't impose. Turning on a strict setting in a large codebase can produce hundreds of
  warnings. Offer the setting, estimate the blast radius (run it once and count), and suggest scoping
  it (one project, one folder, or new code only) if the count is high.
- Never switch a guardrail on in the same commit as the bug fix. It is a separate, reviewable change.
- Rule identifiers below are the ones published by each tool. Where a tool has an equivalent rule
  but the identifier is not listed here, the rule is described instead; check the tool's docs for the
  exact name before adding it to a config.
- The `find_similar.py` preset for each class is listed so you can size the problem first.

Contents: [Python](#python) | [C# / .NET](#c--net) | [TypeScript / JavaScript](#typescript--javascript) |
[Java](#java) | [SQL (any language)](#sql-any-language) | [Test ideas that catch whole classes](#test-ideas-that-catch-whole-classes)

---

## Python

### Missing dict key (KeyError) - preset `python-dict-key-access`

Root cause is usually an untyped dict crossing a boundary (JSON, config, API payload) where a key is
optional in practice.

- **Type the shape** with `TypedDict` and mark optional keys `NotRequired[...]` (Python 3.11+, or
  `typing_extensions`). With pyright, reading a `NotRequired` key without a check is reported by
  `reportTypedDictNotRequiredAccess` (reported by default; set it explicitly so nobody turns it off):

  ```toml
  # pyproject.toml
  [tool.pyright]
  typeCheckingMode = "standard"
  reportTypedDictNotRequiredAccess = "error"
  ```

  mypy reports keys that are not declared on the TypedDict at all, but does not complain about direct
  access to a `NotRequired` key, so on mypy prefer parsing at the boundary (next point).
- **Parse at the boundary** into a dataclass or a validation model (pydantic, attrs) so a missing key
  fails once, at the edge, with a clear message, instead of deep inside business logic.
- **mypy strict** catches the related `None` bugs (`Optional` values used without a check, error code
  `union-attr`):

  ```toml
  [tool.mypy]
  strict = true
  ```

### Bare `except:` / swallowing everything - preset `python-bare-except`

- Ruff `E722` (bare-except; on by default in Ruff's default rule set) and `BLE001` (blind-except,
  catches `except Exception:` / `except BaseException:` that do not re-raise):

  ```toml
  [tool.ruff.lint]
  extend-select = ["E722", "BLE001"]
  ```

- flake8 equivalents: `E722` (pycodestyle) and the flake8-blind-except plugin for broad `except
  Exception:`. If unsure which flake8 plugins are installed, prefer the Ruff config above.

### Mutable default arguments - preset `python-mutable-default-arg`

- Ruff `B006` (mutable-argument-default) and `B008` (function call in a default argument):

  ```toml
  [tool.ruff.lint]
  extend-select = ["B006", "B008"]
  ```

  flake8-bugbear uses the same codes. The fix pattern is `def f(items=None): items = [] if items is None else items`.

### SQL built with f-strings / `%` / `+` - preset `sql-string-concat`

- Ruff `S608` (hardcoded-sql-expression, from flake8-bandit) and Bandit `B608`:

  ```toml
  [tool.ruff.lint]
  extend-select = ["S608"]
  ```

- Use the driver's parameters: `cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))`
  (psycopg / MySQL drivers) or `?` placeholders (sqlite3, pyodbc). For SQLAlchemy use `text()` with
  bound parameters: `conn.execute(text("... WHERE id = :id"), {"id": user_id})`.

---

## C# / .NET

### Null dereference and `.Value` on an empty Nullable<T> - preset `csharp-nullable-value`

Turn on nullable reference types and make the nullable warnings fail the build. The relevant
warnings include **CS8602** (dereference of a possibly null reference), **CS8604** (possible null
reference argument), **CS8618** (non-nullable member not initialised) and **CS8629** (nullable value
type may be null, which is exactly `x.Value` on a `T?` that might be empty).

```xml
<!-- Directory.Build.props (whole repo) or one .csproj -->
<Project>
  <PropertyGroup>
    <Nullable>enable</Nullable>
    <!-- all nullable warnings become errors, other warnings unchanged -->
    <WarningsAsErrors>$(WarningsAsErrors);nullable</WarningsAsErrors>
  </PropertyGroup>
</Project>
```

The stricter option is `<TreatWarningsAsErrors>true</TreatWarningsAsErrors>` (every warning fails the
build). For a large legacy codebase, enable per file with `#nullable enable` at the top of the files
you touch, or per project, and ratchet outwards.

Fix pattern: decide what empty means (`order.Discount ?? 0m`, `GetValueOrDefault()`, or an early
return). Do not add `!` (the null-forgiving operator) to silence the warning; that is the C# version
of the TypeScript non-null assertion.

### `async void` - preset `csharp-async-void`

- Analyzer **VSTHRD100** "Avoid async void methods" from the `Microsoft.VisualStudio.Threading.Analyzers`
  NuGet package (works in any .NET project, not only Visual Studio extensions):

  ```xml
  <ItemGroup>
    <PackageReference Include="Microsoft.VisualStudio.Threading.Analyzers" Version="<current>" PrivateAssets="all" />
  </ItemGroup>
  ```

  ```ini
  # .editorconfig
  [*.cs]
  dotnet_diagnostic.VSTHRD100.severity = error
  ```

- SonarAnalyzer for C# has an equivalent "async methods should not return void" rule.
- Event handlers are the one accepted use; keep their body inside a try/catch that logs.

### `.First()` / `.Single()` on a sequence that can be empty - preset `csharp-first-without-default`

No built-in analyzer can know whether a sequence may be empty. Guardrails:

- Use `FirstOrDefault()` and handle the default explicitly, or `.First()` only after a documented
  invariant ("a customer always has at least one address; enforced in `CustomerFactory`").
- Add a boundary test with an empty collection for every public method that calls `.First()`/`.Single()`
  on input it does not own (see test ideas below).
- With nullable reference types on, `FirstOrDefault()` on a reference-type sequence returns `T?`, so the
  compiler then forces the null check (CS8602).

### SQL built by concatenation or interpolation - preset `sql-string-concat`

- **CA2100** "Review SQL queries for security vulnerabilities" (built into the .NET SDK analyzers):

  ```ini
  # .editorconfig
  [*.cs]
  dotnet_diagnostic.CA2100.severity = error
  ```

- Use `SqlCommand` parameters (`cmd.Parameters.Add("@name", SqlDbType.NVarChar, 100).Value = name;`),
  Dapper parameters (`conn.Query<T>("... WHERE Name = @name", new { name })`), or in EF Core
  `FromSqlInterpolated` / `FromSql` (which turn interpolation holes into parameters) rather than
  `FromSqlRaw` with a concatenated string.

---

## TypeScript / JavaScript

### Non-null assertions and undefined access - preset `js-ts-non-null-assertion`

```jsonc
// tsconfig.json
{
  "compilerOptions": {
    "strict": true,                    // includes strictNullChecks
    "noUncheckedIndexedAccess": true   // arr[i] and record[key] are T | undefined (not part of "strict")
  }
}
```

```js
// eslint.config.js (flat config, typescript-eslint)
import tseslint from "typescript-eslint";

export default [
  ...tseslint.configs.recommended,
  {
    rules: {
      "@typescript-eslint/no-non-null-assertion": "error",
    },
  },
];
```

Fix pattern: narrow instead of asserting (`if (!user) return ...;`, optional chaining with an explicit
fallback `user?.name ?? "guest"`), or make the type honest so the value cannot be undefined.

### Loose equality - preset `js-loose-equality`

```js
rules: {
  eqeqeq: ["error", "always", { null: "ignore" }],  // or "smart", which also allows typeof and literal comparisons
}
```

Why it matters: `0 == ""`, `"1" == 1`, `[] == false` and `null == undefined` are all `true`.

### `parseInt` without a radix - preset `js-parseInt-no-radix`

```js
rules: {
  radix: "error",
}
```

Without a radix, `parseInt("0x1A")` returns 26 (hex) while `parseInt("0x1A", 10)` returns 0. Consider
`Number(x)` plus `Number.isInteger` when the whole string must be numeric (`parseInt("12abc", 10)` is 12).

### SQL in Node - preset `sql-string-concat`

Use placeholders (`$1` for node-postgres, `?` for mysql2, named parameters in most ORMs) or a tagged
template from your SQL library that turns `${value}` into a bound parameter. Never pass a template
literal with `${...}` to a plain `query(string)` call.

---

## Java

### `Optional.get()` without a presence check - preset `java-optional-get`

- IntelliJ IDEA inspection "Optional.get() is called without isPresent() check"; SonarJava has an
  equivalent rule ("Optional value should only be accessed after calling isPresent()").
- Prefer `orElseThrow(() -> new NotFoundException(id))` (states the intent and the error), `orElse`,
  `map`/`ifPresent`. Plain `orElseThrow()` (Java 10+) behaves like `get()` but reads as a deliberate choice.
- Error Prone also ships Optional-misuse checks; see its bug-pattern list for the ones your version has.

### Comparing strings with `==` - preset `java-equals-on-strings`

- SpotBugs **ES_COMPARING_STRINGS_WITH_EQ** and **ES_COMPARING_PARAMETER_STRING_WITH_EQ**.
- Error Prone has reference-equality checks (enabled as warnings by default); promote warnings to
  errors with `-Werror`.
- Fix pattern: `"admin".equals(role)` (null-safe) or `Objects.equals(a, b)`.

```xml
<!-- Maven: fail the build on SpotBugs findings -->
<plugin>
  <groupId>com.github.spotbugs</groupId>
  <artifactId>spotbugs-maven-plugin</artifactId>
  <version><!-- current release --></version>
  <configuration>
    <effort>Max</effort>
    <threshold>Low</threshold>
    <failOnError>true</failOnError>
  </configuration>
  <executions>
    <execution>
      <goals><goal>check</goal></goals>
    </execution>
  </executions>
</plugin>
```

```groovy
// Gradle: Error Prone via the net.ltgt.errorprone plugin
plugins {
    id "net.ltgt.errorprone" version "<current>"
}
dependencies {
    errorprone "com.google.errorprone:error_prone_core:<current>"
}
tasks.withType(JavaCompile).configureEach {
    options.errorprone.disableWarningsInGeneratedCode = true
    options.compilerArgs += ["-Werror"]
}
```

### SQL built by concatenation / `String.format` - preset `sql-string-concat`

- SpotBugs **SQL_NONCONSTANT_STRING_PASSED_TO_EXECUTE** and
  **SQL_PREPARED_STATEMENT_GENERATED_FROM_NONCONSTANT_STRING**.
- Use `PreparedStatement` with `?` and `setString`, JPA named parameters (`:name`), or jOOQ / Spring
  `JdbcTemplate` with bind arguments.

---

## SQL (any language)

- **Parameterise, always.** Values go in parameters; only identifiers (table/column names) may be
  built dynamically, and then only from an allow-list.
- **T-SQL dynamic SQL:** `EXEC sp_executesql @sql, N'@Name nvarchar(100)', @Name = @Name;` instead of
  `EXEC(@sql)` with the value concatenated in. Wrap dynamic identifiers in `QUOTENAME()`.
- **PL/SQL:** `EXECUTE IMMEDIATE v_sql USING p_name;` / `OPEN c FOR v_sql USING p_name;` with `:1`
  placeholders instead of `||` concatenation. `DBMS_ASSERT` for identifiers.
- **Review gate:** a SQL-injection finding is a security defect. If the concatenated value can come
  from a user, stop and route it to the security-defect process instead of fixing it as an ordinary bug.

---

## Test ideas that catch whole classes

A guardrail can also be a test that would have caught this bug and its siblings:

| Bug class | Test that catches the class |
|---|---|
| Missing key / null / empty value | Boundary tests: missing key, `None`/`null`, empty string, empty list, whitespace. Parametrise one test over all of them. |
| `.First()` / `[0]` / `.get()` on empty | Same test with an empty collection / empty Optional; assert the documented behaviour (default, error type and message). |
| Parsing (`parseInt`, dates, money) | Property-based test: for any valid value, `parse(format(x)) == x`. Also leading zeros, `"0x"` prefixes, locale separators. |
| Loose equality / coercion | Table test with the coercion traps: `0` vs `""`, `"1"` vs `1`, `null` vs `undefined`, `false` vs `[]`. |
| Mutable defaults / shared state | Call the function twice in the same test and assert the second call is not affected by the first. |
| SQL concatenation | Feed a value containing a quote (`O'Brien`) and assert the query still works; that fails on concatenated SQL and passes on parameters. |
| Async void / unobserved exceptions | Make the dependency throw and assert the caller observes the exception (it cannot with `async void`). |

Property-based testing libraries: Hypothesis (Python), fast-check (JS/TS), FsCheck or CsCheck (.NET),
jqwik (Java), `testing/quick` or rapid (Go). One property test often replaces a dozen example tests
for parsers and converters.
