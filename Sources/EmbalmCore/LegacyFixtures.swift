// Known-good containers written by earlier format versions, used by the
// self-check to prove old files keep opening. Password for all: fixture-pass
enum LegacyFixtures {
    struct Fixture { let name: String; let base64: String; let plaintext: String }
    static let all: [Fixture] = [
        Fixture(name: "v1 (PBKDF2, fingerprinted)", base64: "RU1CQUxNAQEBAAknwAIAEJUaUfjVFMlYgJyfPBGQPQ1jpJAAxgj2rUWZ89UAMLeLKAnnPkqzmrRytN6G8LQ5A5/6dq/9lv4qY1U8ZBEC3ErVQhkefoIfUXKRox8v0kHbBnDPxYhs3AdtQQAAAAAAAAARFne8OlojgOKb6kwROMlekVxlouXI7Xw7rkwecJKuIs8AAAAAAAAAIQn/LQAGKwNzLYE5KuPgwW9WhJJ3psnItppCh++hYUEfAw==", plaintext: "legacy-fixture-v1"),
        Fixture(name: "v2 (Argon2id)", base64: "RU1CQUxNAgECAxABAAIAEN3wHJ+PIj3zU/xAr2vp+XuYrL6OagEFWVm3UhYAMOfCZt9Bo4jfNBSOiWduh+TOj1qy6WVgE0uVHupWdNy/ReXfmDNAxa1XRnbse8xuK7xdDDGTrhhNnEbtBwAAAAAAAAAn019Fe9aMQUKs7DxA81Do6iBoGp8O3OsYt2hTio/2OBRX9A0hS3YS", plaintext: "legacy-fixture-v2-argon"),
        Fixture(name: "v2 (PBKDF2)", base64: "RU1CQUxNAgEBAAGGoAIAEHRnsNq+T9iWISJuzKZREVZ7EX3Be034vl/wHLYAMDtzm3KWwSVZw+TnXofKAHiZyNxIhQYDMoivpHiDAIObVffJT/S1HZ6Zcx33MUOn6JciqrWEqTFEsWA3cAAAAAAAAAAoj1uzRnQu6mT4VesbFR8G2OoZYn7bLn3V3O+00uJXxrIhXtOWDovkrg==", plaintext: "legacy-fixture-v2-pbkdf2"),
    ]
}
