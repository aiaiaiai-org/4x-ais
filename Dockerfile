# © 2026 aiaiaiai · aiaiaiai.org
# SPDX-License-Identifier: Apache-2.0
FROM rust:1.98-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src src
COPY static static
RUN cargo build --release --locked

FROM debian:bookworm-slim
COPY --from=build /src/target/release/ais /usr/local/bin/ais
# The database lives on a volume mounted at /data, owned by the service user.
RUN mkdir /data && chown 65532:65532 /data
USER 65532:65532
ENV AIS_DATABASE_URL=sqlite:///data/ais.db
EXPOSE 1927
CMD ["/usr/local/bin/ais"]
