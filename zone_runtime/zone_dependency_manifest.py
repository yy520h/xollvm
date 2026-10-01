from dataclasses import dataclass


@dataclass(frozen=True)
class DependencySpec:
    name: str
    link_names: tuple[str, ...]
    required_symbols: tuple[str, ...]
    private_prefix: str


DEPENDENCIES = {
    "curl": DependencySpec(
        "curl", ("curl",), ("curl_easy_init", "curl_easy_perform"),
        "xollvm_zone_curl_"
    ),
    "zlib": DependencySpec(
        "zlib", ("z", "zlib"), ("deflate", "inflate"), "xollvm_zone_zlib_"
    ),
    "ssl": DependencySpec(
        "ssl", ("ssl",), ("SSL_CTX_new", "SSL_new"), "xollvm_zone_ssl_"
    ),
    "crypto": DependencySpec(
        "crypto", ("crypto",), ("EVP_sha256", "EVP_DigestInit_ex"),
        "xollvm_zone_crypto_"
    ),
}
