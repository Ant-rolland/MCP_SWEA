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


def test_discovers_literal_framework_route_registration_calls(tmp_path):
    (tmp_path / "routes.py").write_text(
        "app.add_api_route('/fastapi', fast_handler, methods=['GET', 'POST'])\n"
        "app.add_url_rule('/flask', view_func=flask_handler, methods=['PATCH'])\n"
        "app.add_url_rule('/flask-default', 'flask_default', default_handler)\n"
        "app.add_route('/starlette', starlette_handler, methods=['DELETE'])\n"
        "app.add_api_route(DYNAMIC_PATH, dynamic_handler)\n"
        "app.add_route('/dynamic-methods', handler, methods=METHODS)\n",
        encoding="utf-8",
    )

    report = discover_python_routes(tmp_path)

    signatures = {(item["method"], item["path"]) for item in report["routes"]}
    assert signatures == {
        ("GET", "/fastapi"),
        ("POST", "/fastapi"),
        ("PATCH", "/flask"),
        ("GET", "/flask-default"),
        ("DELETE", "/starlette"),
    }
    by_path = {item["path"]: item["function"] for item in report["routes"]}
    assert by_path["/fastapi"] == "fast_handler"
    assert by_path["/flask"] == "flask_handler"


def test_composes_nested_fastapi_router_prefixes(tmp_path):
    (tmp_path / "nested.py").write_text(
        "from fastapi import APIRouter, FastAPI\n"
        "app = FastAPI()\n"
        "root_router = APIRouter(prefix='/v1')\n"
        "items_router = APIRouter(prefix='/items')\n"
        "@items_router.get('/')\n"
        "def list_items(): pass\n"
        "root_router.include_router(items_router, prefix='/catalog')\n"
        "app.include_router(root_router, prefix='/api')\n"
        "app.include_router(root_router, prefix='/internal')\n",
        encoding="utf-8",
    )

    report = discover_python_routes(tmp_path)

    signatures = {(item["method"], item["path"]) for item in report["routes"]}
    assert signatures == {
        ("GET", "/api/v1/catalog/items"),
        ("GET", "/internal/v1/catalog/items"),
    }


def test_nested_router_with_dynamic_mount_prefix_is_not_guessed(tmp_path):
    (tmp_path / "nested.py").write_text(
        "root_router = APIRouter(prefix='/v1')\n"
        "items_router = APIRouter(prefix='/items')\n"
        "@items_router.get('/')\n"
        "def list_items(): pass\n"
        "root_router.include_router(items_router, prefix=ITEMS_PREFIX)\n"
        "app.include_router(root_router, prefix='/api')\n",
        encoding="utf-8",
    )

    report = discover_python_routes(tmp_path)

    assert report["routes"] == []


def test_maps_routes_through_literal_imported_fastapi_router(tmp_path):
    app = tmp_path / "app"
    routers = app / "routers"
    routers.mkdir(parents=True)
    (app / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "from .routers.users import router as users_router\n"
        "app = FastAPI()\n"
        "app.include_router(users_router, prefix='/api')\n",
        encoding="utf-8",
    )
    (routers / "users.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter(prefix='/users')\n"
        "@router.get('/items')\n"
        "def list_items():\n"
        "    return []\n",
        encoding="utf-8",
    )

    report = discover_python_routes(tmp_path)

    assert any(
        route["method"] == "GET"
        and route["path"] == "/api/users/items"
        and route["source_path"] == "app/routers/users.py"
        for route in report["routes"]
    )


def test_cross_module_router_mount_with_dynamic_prefix_is_not_mapped(tmp_path):
    app = tmp_path / "app"
    routers = app / "routers"
    routers.mkdir(parents=True)
    (app / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "from .routers.users import router as users_router\n"
        "app = FastAPI()\n"
        "app.include_router(users_router, prefix=runtime_prefix)\n",
        encoding="utf-8",
    )
    (routers / "users.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter(prefix='/users')\n"
        "@router.get('/items')\n"
        "def list_items():\n"
        "    return []\n",
        encoding="utf-8",
    )

    report = discover_python_routes(tmp_path)

    assert not any(
        route["method"] == "GET"
        and route["source_path"] == "app/routers/users.py"
        for route in report["routes"]
    )

def test_maps_routes_through_multi_module_router_mount_chain(tmp_path):
    app = tmp_path / "app"
    routers = app / "routers"
    nested = routers / "nested"
    nested.mkdir(parents=True)
    (app / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "from .routers.root import router as root_router\n"
        "app = FastAPI()\n"
        "app.include_router(root_router, prefix='/api')\n",
        encoding="utf-8",
    )
    (routers / "root.py").write_text(
        "from fastapi import APIRouter\n"
        "from .nested.users import router as users_router\n"
        "router = APIRouter(prefix='/v1')\n"
        "router.include_router(users_router, prefix='/accounts')\n",
        encoding="utf-8",
    )
    (nested / "users.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter(prefix='/users')\n"
        "@router.get('/{user_id}')\n"
        "def get_user(user_id: str):\n"
        "    return {'id': user_id}\n",
        encoding="utf-8",
    )

    report = discover_python_routes(tmp_path)

    assert any(
        route["method"] == "GET"
        and route["path"] == "/api/v1/accounts/users/{user_id}"
        and route["source_path"] == "app/routers/nested/users.py"
        for route in report["routes"]
    )


def test_does_not_guess_multi_module_router_chain_with_dynamic_parent_prefix(tmp_path):
    app = tmp_path / "app"
    routers = app / "routers"
    nested = routers / "nested"
    nested.mkdir(parents=True)
    (app / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "from .routers.root import router as root_router\n"
        "app = FastAPI()\n"
        "app.include_router(root_router, prefix='/api')\n",
        encoding="utf-8",
    )
    (routers / "root.py").write_text(
        "from fastapi import APIRouter\n"
        "from .nested.users import router as users_router\n"
        "router = APIRouter(prefix='/v1')\n"
        "router.include_router(users_router, prefix=runtime_prefix)\n",
        encoding="utf-8",
    )
    (nested / "users.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter(prefix='/users')\n"
        "@router.get('/')\n"
        "def list_users():\n"
        "    return []\n",
        encoding="utf-8",
    )

    report = discover_python_routes(tmp_path)

    assert not any(
        route["source_path"] == "app/routers/nested/users.py"
        for route in report["routes"]
    )

