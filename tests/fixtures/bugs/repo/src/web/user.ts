interface User { name?: string; age?: number }

export function greet(user: User | undefined): string {
  const name = user!.name;
  let later!: string;
  if (user != null && user.age == 18) {
    return name!;
  }
  const n = parseInt(user!.age as unknown as string);
  const m = parseInt("42", 10);
  const k = Number.parseInt(String(user?.age));
  if (typeof user == "undefined") { return ""; }
  if (name === "x" || name !== "y") { return name; }
  return `${name}`;
}
