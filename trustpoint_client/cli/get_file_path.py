import click


@click.group(name='get-file-path')
def get_file_path():
    """Returns the file path of an object (read-only)."""