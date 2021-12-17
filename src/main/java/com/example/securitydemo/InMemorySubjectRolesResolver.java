package com.example.securitydemo;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Component;

/**
 * In-memory implementation of {@link SubjectRolesResolver} that uses hard-coded
 * map of subjects to their roles. Used for demo purposes only.
 */
@Component
public class InMemorySubjectRolesResolver implements SubjectRolesResolver {

    private final Map<String, Collection<String>> repository;

    public InMemorySubjectRolesResolver() {
        repository = new ConcurrentHashMap<>();
        repository.put("bob", Collections.singleton("USER"));
        repository.put("dGVzdEBleGFtcGxlLmNvbQ==", Collections.singleton("USER"));
        repository.put("YWRtaW5AZXhhbXBsZS5jb20=", Collections.singleton("ADMIN"));
        repository.put("admin", Collections.singleton("ADMIN"));
    }

    @Override
    public Collection<String> getRolesBySubject(String subject) {
        return Optional.ofNullable(repository.get(subject))
                .orElse(Collections.emptySet());
    }
}
