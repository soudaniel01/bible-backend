package com.api.auth.user.entity;

public enum UserRole {
    SUPER_ADMIN("SUPER_ADMIN", "Pode gerenciar usuários"),
    USER("USER", "Apenas usa o sistema com acesso limitado (ex: consultar dados próprios)");

    private String role;
    private String description;

    UserRole(String role, String description) {
        this.role = role;
        this.description = description;
    }

    public String getRole() {
        return this.role;
    }

    public String getDescription() {
        return this.description;
    }

    /**
     * Verifica se o role atual tem permissão para gerenciar o role alvo
     * @param targetRole o role que se deseja gerenciar
     * @return true se tem permissão, false caso contrário
     */
    public boolean canManage(UserRole targetRole) {
        switch (this) {
            case SUPER_ADMIN:
                return targetRole == USER;
            case USER:
            default:
                return false;
        }
    }

    /**
     * Verifica se o role atual é superior ao role alvo na hierarquia
     * @param targetRole o role para comparar
     * @return true se é superior, false caso contrário
     */
    public boolean isHigherThan(UserRole targetRole) {
        return this.ordinal() < targetRole.ordinal();
    }
}
