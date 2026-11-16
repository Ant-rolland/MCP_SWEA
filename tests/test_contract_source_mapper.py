from swea_sentinel.core.contract_source_mapper import discover_python_routes


def test_discovers_only_literal_route_paths_and_methods(tmp_path):
    (tmp_path / "api.py").write_text(
        "PATH = '/dynamic'\n"
        "@app.get('/items')\n"
        "def list_items(): pass\n"
        "@app.route('/health', methods=['GET', 'POST'])\n"
        "def health(): pass\n"
        "@app.get(PATH)\n"
        "def dynamic(): pass\n"
        "@app.get('/items/' + '{item_id}')\n"
        "def composed(): pass\n",
        encoding="utf-8",
    )

    report = discover_python_routes(tmp_path)

    signatures = {(item["method"], item["path"]) for item in report["routes"]}
    assert signatures == {
        ("GET", "/items"),
        ("GET", "/health"),
        ("POST", "/health"),
    }
    assert all(item["source_path"] == "api.py" for item in report["routes"])
    assert all(len(item["sha256"]) == 64 for item in report["routes"])


def test_route_scan_is_bounded_by_file_count(tmp_path):
    (tmp_path / "a.py").write_text("@app.get('/a')\ndef a(): pass\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("@app.get('/b')\ndef b(): pass\n", encoding="utf-8")

    report = discover_python_routes(tmp_path, max_files=1)

    assert report["files_scanned"] == 1
    assert report["truncated"] is True
    assert report["truncated_reason"] == "maximum_file_count"


def test_composes_literal_fastapi_router_and_mount_prefixes(tmp_path):
    (tmp_path / "api.py").write_text(
        "from fastapi import APIRouter, FastAPI\n"
        "app = FastAPI()\n"
        "router = APIRouter(prefix='/items')\n"
        "@router.get('/')\n"
        "def list_items(): pass\n"
        "app.include_router(router, prefix='/api/v1')\n"
        "app.include_router(router, prefix='/internal')\n",
        encoding="utf-8",
    )

    report = discover_python_routes(tmp_path)

    signatures = {(item["method"], item["path"]) for item in report["routes"]}
    assert signatures == {
        ("GET", "/api/v1/items"),
        ("GET", "/internal/items"),
    }


def test_skips_router_mapping_when_prefix_is_dynamic(tmp_path):
    (tmp_path / "api.py").write_text(
        "router = APIRouter(prefix=API_PREFIX)\n"
        "@router.get('/items')\n"
        "def list_items(): pass\n",
        encoding="utf-8",
    )

    report = discover_python_routes(tmp_path)

    assert report["routes"] == []
