from ipywidgets import DOMWidget
from traitlets import Unicode


class SecretsWidget(DOMWidget):
    """A notebook widget that stores and retrieves a secret via the JupyterLab
    secrets manager.

    The secret value is entered by the user in the rendered input field and
    synced to the Python kernel through the ipywidgets comm channel.  The
    value is also persisted in the active secrets-manager connector so it
    survives re-renders within the same session.

    Parameters
    ----------
    label:
        Text label shown next to the input field.
    secret_id:
        Unique key used to store/retrieve the secret in the manager.  Two
        widgets sharing the same ``secret_id`` will share the same stored
        value.

    Example
    -------
    >>> from jupyter_secrets_manager import SecretsWidget
    >>> w = SecretsWidget(label='OpenAI API key', secret_id='openai-api-key')
    >>> display(w)
    >>> # user types the key in the rendered widget …
    >>> api_key = w.value
    """

    _model_name = Unicode('SecretsModel').tag(sync=True)
    _model_module = Unicode('jupyter-secrets-manager').tag(sync=True)
    _model_module_version = Unicode('0.5.0').tag(sync=True)
    _view_name = Unicode('SecretsView').tag(sync=True)
    _view_module = Unicode('jupyter-secrets-manager').tag(sync=True)
    _view_module_version = Unicode('0.5.0').tag(sync=True)

    label = Unicode('Secret').tag(sync=True)
    secret_id = Unicode('').tag(sync=True)
    value = Unicode('').tag(sync=True)
