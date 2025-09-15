FROM maven:3.9.11-eclipse-temurin-17

WORKDIR /opt

# Install minimal tools
RUN apt-get update \
    && apt-get install -y --no-install-recommends git curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Clone OWASP Benchmark (Java) and prefetch dependencies to speed up later starts
RUN git clone --depth=1 https://github.com/OWASP-Benchmark/BenchmarkJava.git \
    && cd BenchmarkJava \
    && mvn -q -B -DskipTests=true -Denforcer.skip=true initialize

WORKDIR /opt/BenchmarkJava

# Expose Tomcat HTTPS port used by the cargo plugin
EXPOSE 8443

# Run the remote-accessible profile which binds to 0.0.0.0:8443 (HTTPS)
# Note: first run downloads Tomcat and builds the WAR; subsequent starts are faster.
# We skip maven-enforcer as the project’s jvm.config requires JDK9+ flags while POM targets Java 8.
CMD ["sh", "-lc", "mvn -q initialize -Denforcer.skip=true && mvn -q clean package cargo:run -Pdeploy -Drunenv=remote -Denforcer.skip=true"]
