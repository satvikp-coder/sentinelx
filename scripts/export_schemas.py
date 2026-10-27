"""Regenerate packages/common_schemas/schemas/*.schema.json (run from anywhere)."""

from sentinelx.common_schemas import write_schema_files

if __name__ == "__main__":
    for path in write_schema_files():
        print("wrote", path)
