import { greet } from "./user";

test("greets a guest", () => {
  const u = { name: "a" };
  expect(greet(u)!.length).toBe(1);
  expect(parseInt("1")).toBe(1);
});
