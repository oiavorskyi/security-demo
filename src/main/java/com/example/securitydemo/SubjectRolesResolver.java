package com.example.securitydemo;

import java.util.Collection;

/**
 * Maps JWT token subjects to the roles that should be granted to the users
 * authenticated with this token.
 * <p>
 * Implementations can be as simple as in-memory lists, or they could be based on
 * something like SQL queries.
 */
public interface SubjectRolesResolver {

    /**
     * Returns collection of roles that should be granted to a token with the
     * specified subject.
     */
    Collection<String> getRolesBySubject(String subject);
}
