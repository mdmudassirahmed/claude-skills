package shop;

import java.util.Optional;

class UserServiceTest {
    void nickname() {
        Optional<String> n = Optional.of("a");
        String s = n.get();
        if (s == "a") { }
    }
}
