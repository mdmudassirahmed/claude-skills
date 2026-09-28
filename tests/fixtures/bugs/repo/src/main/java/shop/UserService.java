package shop;

import java.util.List;
import java.util.Optional;

public class UserService {
    private final UserRepository repo;
    private final java.util.function.Supplier<String> supplier = () -> "x";

    public UserService(UserRepository repo) { this.repo = repo; }

    public Optional<String> findNickname(String id) {
        return Optional.ofNullable(id);
    }

    public String nickname(String id) {
        return findNickname(id).get();
    }

    public String byId(String id) {
        return repo.findById(id).get().getName();
    }

    public String guarded(String id) {
        Optional<String> nick = findNickname(id);
        if (nick.isPresent()) {
            return nick.get();
        }
        Optional<String> other = findNickname(id + "x");
        String fallback = other.get();
        return supplier.get() + fallback;
    }

    public boolean isAdmin(String role, String name) {
        if (role == "admin") { return true; }
        if (role != null && name == role) { return true; }
        if (role.equals("root")) { return true; }
        int a = 1, b = 2;
        return a == b;
    }

    public List<User> search(java.sql.Connection conn, String name) throws Exception {
        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
        String sql2 = String.format("SELECT * FROM users WHERE name = '%s'", name);
        java.sql.PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
        return null;
    }
}
