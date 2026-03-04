package com.api.auth.user.entity.converter;

import com.api.auth.user.entity.UserRole;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

@Converter(autoApply = false)
public class UserRoleConverter implements AttributeConverter<UserRole, String> {

    @Override
    public String convertToDatabaseColumn(UserRole attribute) {
        if (attribute == null) return UserRole.USER.name();
        return attribute.name();
    }

    @Override
    public UserRole convertToEntityAttribute(String dbData) {
        if (dbData == null) return UserRole.USER;
        String value = dbData.trim().toUpperCase();
        switch (value) {
            case "SUPER_ADMIN":
                return UserRole.SUPER_ADMIN;
            case "USER":
                return UserRole.USER;
            case "ADMIN":
                // Fallback seguro para legado
                return UserRole.USER;
            default:
                // Qualquer valor inesperado cai para USER (fail-safe)
                return UserRole.USER;
        }
    }
}