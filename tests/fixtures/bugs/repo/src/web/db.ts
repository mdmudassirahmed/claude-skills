export function find(db: any, id: string) {
  return db.query(`SELECT * FROM orders WHERE id = ${id}`);
}

export function findSafe(db: any, id: string) {
  return db.query("SELECT * FROM orders WHERE id = $1", [id]);
}
