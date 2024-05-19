package dev.jeron7.springsecurityexamples.account;

public enum Privileges {
    MANAGER_READ("manager::read"),
    MANAGER_WRITE("manager::write"),
    ADMIN_READ("admin::read"),
    ADMIN_WRITE("admin::write");

    private final String permissionRepresentation;

    Privileges(String permissionRepresentation) {
        this.permissionRepresentation = permissionRepresentation;
    }

    @Override
    public String toString() {
        return permissionRepresentation;
    }
}
