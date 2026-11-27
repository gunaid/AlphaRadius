# ==============================================================================
# Production FreeRADIUS 3.x with MySQL/MariaDB Support & MikroTik Dictionaries
# ==============================================================================
# Layer order matters for update time: the packages and the compiled
# rlm_detail module come from stages that never see the configuration files,
# so editing entrypoint.sh or a policy rebuilds only the final COPY layers
# (seconds, no download) instead of reinstalling the compiler and refetching
# the FreeRADIUS source.
FROM debian:bookworm-slim AS radius-base
ARG FREERADIUS_DEBIAN_VERSION=3.2.1+dfsg-4+deb12u1

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    freeradius=${FREERADIUS_DEBIAN_VERSION} \
    freeradius-mysql=${FREERADIUS_DEBIAN_VERSION} \
    freeradius-utils=${FREERADIUS_DEBIAN_VERSION} \
    mariadb-client \
    curl \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Compile only the checked diagnostic-log close; no compiler enters runtime.
FROM radius-base AS detail-build
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libc6-dev libfreeradius-dev=3.2.1+dfsg-4+deb12u1 \
    libtalloc-dev libssl-dev libpcre3-dev libcap-dev patch xz-utils \
    && rm -rf /var/lib/apt/lists/*
COPY patches/detail-close.patch /detail-close.patch
COPY patches/build-detail.sh /build-detail.sh
RUN sh /build-detail.sh

FROM radius-base
COPY --from=detail-build /build/detail/rlm_detail.so /usr/lib/freeradius/rlm_detail.so
COPY --from=detail-build /build/detail/rlm_detail.c /usr/share/doc/alpha-radius-detail/rlm_detail.c
COPY patches/detail-close.patch /usr/share/doc/alpha-radius-detail/detail-close.patch

# Working directory, entrypoint and configuration (the files that change).
WORKDIR /etc/freeradius/3.0
COPY entrypoint.sh /entrypoint.sh
COPY license-capacity-postauth.conf /etc/freeradius/3.0/license-capacity-postauth.conf
COPY alpha-accounting-identity.conf /etc/freeradius/3.0/policy.d/alpha-accounting-identity
COPY alpha-realm-policy.conf /etc/freeradius/3.0/policy.d/alpha-realm-policy
COPY queries.conf /etc/freeradius/3.0/mods-config/sql/main/mysql/queries.conf
COPY detail /etc/freeradius/3.0/mods-available/detail
RUN chmod +x /entrypoint.sh

# Expose standard FreeRADIUS Ports inside container (Auth & Acct)
EXPOSE 1812/udp
EXPOSE 1813/udp

ENTRYPOINT ["/entrypoint.sh"]
