import {
  JupyterFrontEnd,
  JupyterFrontEndPlugin
} from '@jupyterlab/application';
import { PageConfig } from '@jupyterlab/coreutils';
import { ISettingRegistry } from '@jupyterlab/settingregistry';
import { IJupyterWidgetRegistry } from '@jupyter-widgets/base';

import { SecretsManager } from './manager';
import { ISecretsManager } from './token';
import { InMemoryConnector } from './connectors';
import {
  MODULE_NAME,
  MODULE_VERSION,
  SecretsModel,
  SecretsView,
  setManager
} from './widget';

/**
 * A basic secret connector extension, that should be disabled to provide a new
 * connector.
 */
const inMemoryConnector: JupyterFrontEndPlugin<void> = {
  id: 'jupyter-secrets-manager:connector',
  description: 'A JupyterLab extension to manage secrets.',
  autoStart: true,
  requires: [ISecretsManager],
  activate: (app: JupyterFrontEnd, manager: ISecretsManager): void => {
    manager.setConnector(new InMemoryConnector());
  }
};

/**
 * The secret manager extension.
 */
const managerPlugin: JupyterFrontEndPlugin<ISecretsManager> = {
  id: 'jupyter-secrets-manager:manager',
  description: 'A JupyterLab extension to manage secrets.',
  autoStart: true,
  provides: ISecretsManager,
  optional: [ISettingRegistry],
  activate: (
    app: JupyterFrontEnd,
    settingRegistry: ISettingRegistry
  ): ISecretsManager => {
    // Check if the fields are hidden from page config.
    let showSecretFieldsConfig = true;
    if (PageConfig.getOption('secretsManager-showFields') === 'false') {
      showSecretFieldsConfig = false;
    }

    const manager = new SecretsManager({
      showSecretFields: showSecretFieldsConfig
    });

    settingRegistry
      .load(managerPlugin.id)
      .then(settings => {
        // If the fields are hidden from the manager, remove the setting.
        if (!showSecretFieldsConfig) {
          delete settings.schema.properties?.['ShowSecretFields'];
          return;
        }

        // Otherwise listen to it to update the field visibility.
        const updateFieldVisibility = () => {
          const showSecretField =
            settings.get('ShowSecretFields').composite ?? false;
          manager.secretFieldsVisibility = showSecretField as boolean;
        };

        settings.changed.connect(() => updateFieldVisibility());
        updateFieldVisibility();
      })
      .catch(reason => {
        console.error(
          `Failed to load settings for ${managerPlugin.id}`,
          reason
        );
      });

    console.debug('JupyterLab extension jupyter-secrets-manager is activated!');
    return manager;
  }
};

/**
 * A notebook widget plugin that bridges ipywidgets comm with the secrets manager.
 */
const widgetPlugin = SecretsManager.sign(
  'jupyter-secrets-manager:widget',
  (token: symbol | null) => ({
    id: 'jupyter-secrets-manager:widget',
    description: 'Notebook widget bridge for the secrets manager.',
    autoStart: true,
    requires: [ISecretsManager],
    optional: [IJupyterWidgetRegistry],
    activate: (
      app: JupyterFrontEnd,
      manager: ISecretsManager,
      widgetRegistry: IJupyterWidgetRegistry | null
    ): void => {
      if (!token) {
        return;
      }
      setManager(manager, token);
      if (widgetRegistry) {
        widgetRegistry.registerWidget({
          name: MODULE_NAME,
          version: MODULE_VERSION,
          exports: { SecretsModel, SecretsView }
        });
      }
    }
  })
);

export * from './connectors';
export * from './manager';
export * from './token';
export * from './widget';
export default [inMemoryConnector, managerPlugin, widgetPlugin];
