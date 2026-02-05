"""CLI command to run the REST API server."""

import click


@click.command("serve")
@click.option("--host", default="0.0.0.0", help="Host to bind to")
@click.option("--port", default=8000, help="Port to bind to")
@click.option("--reload", is_flag=True, help="Enable auto-reload for development")
@click.option("--workers", default=1, help="Number of workers")
def serve(host: str, port: int, reload: bool, workers: int):
    """Start the DeployGuard REST API server.
    
    Example:
        deployguard serve --port 8080
        deployguard serve --reload  # for development
    """
    try:
        import uvicorn
    except ImportError:
        click.echo("Error: uvicorn is not installed.", err=True)
        click.echo("Install with: pip install 'deployguard-repo-guard[api]'", err=True)
        raise SystemExit(1)
    
    click.echo(f"Starting DeployGuard API server on {host}:{port}")
    click.echo("API docs available at: http://{}:{}/docs".format(
        "localhost" if host == "0.0.0.0" else host, port
    ))
    
    uvicorn.run(
        "deployguard.api.app:app",
        host=host,
        port=port,
        reload=reload,
        workers=workers if not reload else 1,
    )
