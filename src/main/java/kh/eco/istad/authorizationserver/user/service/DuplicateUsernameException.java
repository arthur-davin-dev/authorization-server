package kh.eco.istad.authorizationserver.user.service;

public class DuplicateUsernameException extends RuntimeException {
    public DuplicateUsernameException() {
        super("Username is already registered");
    }
}
