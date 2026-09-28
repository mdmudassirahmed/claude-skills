import os


def build(data):
    title = data["title"]
    home = os.environ["HOME"]
    cur = data["currency"]
    items = ["a", "b"]
    first = items[0]
    return title, home, cur, first


def query_user(cursor, user_id, name):
    cursor.execute("SELECT * FROM users WHERE id = " + str(user_id))
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    cursor.execute("DELETE FROM users WHERE id = %s" % user_id)
    msg = "Tell us where you live: " + name
    return msg


def cache(key, store={}):
    return store
