#!/usr/bin/env node
/**
 * ARES CLI
 *
 * Command-line interface for ARES operations.
 */

import { Command } from 'commander';
import inquirer from 'inquirer';
import chalk from 'chalk';
import boxen from 'boxen';
import ora from 'ora';
import Table from 'cli-table3';
import gradient from 'gradient-string';
import figlet from 'figlet';

import {
  createAutoAres,
  createTestAres,
  createStealthOperation,
  createAggressiveOperation,
  getBanner,
  type Ares,
  type OperatorArchetype,
} from './index.js';

import {
  config,
  hasApiKey,
  setApiKey,
  getConfiguredProviders,
  AVAILABLE_MODELS,
} from './config/index.js';

import { LLMBackbone } from './llm/index.js';

// =============================================================================
// DISPLAY HELPERS
// =============================================================================

function showBanner(): void {
  try {
    const text = figlet.textSync('ARES', {
      font: 'ANSI Shadow',
      horizontalLayout: 'default',
    });
    console.log(gradient.pastel.multiline(text));
  } catch {
    console.log(chalk.cyan(getBanner()));
  }
  console.log(chalk.gray('  Tactical Execution Multi-agent Platform for Elite Security Testing\n'));
}

function showBox(title: string, content: string, borderColor: string = 'cyan'): void {
  console.log(
    boxen(content, {
      title,
      titleAlignment: 'center',
      padding: 1,
      margin: { top: 0, bottom: 1, left: 1, right: 1 },
      borderStyle: 'round',
      borderColor: borderColor as any,
    })
  );
}

function showSuccess(message: string): void {
  console.log(chalk.green('✓ ') + message);
}

function showError(message: string): void {
  console.log(chalk.red('✗ ') + message);
}

function showInfo(message: string): void {
  console.log(chalk.blue('ℹ ') + message);
}

function showWarning(message: string): void {
  console.log(chalk.yellow('⚠ ') + message);
}

// =============================================================================
// STATUS DISPLAY
// =============================================================================

function displayStatus(ares: Ares): void {
  const status = ares.command.getStatus();

  console.log('');
  console.log(chalk.bold.cyan('═══ OPERATION STATUS ═══'));
  console.log('');

  // Operation Info
  console.log(chalk.bold('Operation:'), status.name);
  console.log(chalk.bold('Status:'), status.running
    ? (status.paused ? chalk.yellow('PAUSED') : chalk.green('RUNNING'))
    : chalk.gray('STOPPED'));
  console.log(chalk.bold('Tick Count:'), status.tickCount);
  console.log('');

  // Operators Table
  const opTable = new Table({
    head: [
      chalk.cyan('Status'),
      chalk.cyan('Count'),
    ],
    style: { head: [], border: [] },
  });

  opTable.push(
    ['Available', chalk.green(status.operators.available.toString())],
    ['Busy', chalk.yellow(status.operators.busy.toString())],
    ['Cooldown', chalk.blue(status.operators.cooldown.toString())],
    ['Burned', chalk.red(status.operators.burned.toString())],
    [chalk.bold('Total'), chalk.bold(status.operators.total.toString())],
  );

  console.log(chalk.bold('Operators:'));
  console.log(opTable.toString());
  console.log('');

  // Findings Summary
  const findingsTable = new Table({
    head: [
      chalk.cyan('Severity'),
      chalk.cyan('Count'),
    ],
    style: { head: [], border: [] },
  });

  findingsTable.push(
    [chalk.red('Critical'), status.vault.bySeverity.critical.toString()],
    [chalk.magenta('High'), status.vault.bySeverity.high.toString()],
    [chalk.yellow('Medium'), status.vault.bySeverity.medium.toString()],
    [chalk.blue('Low'), status.vault.bySeverity.low.toString()],
    [chalk.gray('Info'), status.vault.bySeverity.info.toString()],
  );

  console.log(chalk.bold('Findings:'));
  console.log(findingsTable.toString());
  console.log('');

  // OPSEC Status
  const opsecColor = status.opsec.riskLevel === 'critical' ? chalk.red :
    status.opsec.riskLevel === 'high' ? chalk.yellow :
    status.opsec.riskLevel === 'medium' ? chalk.blue : chalk.green;

  console.log(chalk.bold('OPSEC:'), opsecColor(status.opsec.riskLevel.toUpperCase()));
  console.log(chalk.bold('Detections:'), `${status.opsec.activeDetections}/${status.opsec.totalDetections}`);

  if (status.opsec.abortRecommended) {
    console.log(chalk.red.bold('⚠ ABORT RECOMMENDED'));
  }

  console.log('');
}

// =============================================================================
// INTERACTIVE MODE
// =============================================================================

async function interactiveMode(): Promise<void> {
  showBanner();

  // Check for API keys
  const providers = getConfiguredProviders().filter(p => p !== 'mock');

  if (providers.length === 0) {
    showBox(
      'Setup Required',
      `No API keys configured. Please run setup first:

${chalk.cyan('npx ares setup')}

Or set environment variables:
${chalk.gray('OPENROUTER_API_KEY=your-key-here')}`,
      'yellow'
    );

    const { runSetup } = await inquirer.prompt([
      {
        type: 'confirm',
        name: 'runSetup',
        message: 'Would you like to run setup now?',
        default: true,
      },
    ]);

    if (runSetup) {
      // Run setup
      const { execSync } = await import('child_process');
      execSync('npx tsx src/setup.ts', { stdio: 'inherit' });
    }
    return;
  }

  // Welcome message
  showBox(
    'Welcome to ARES',
    `Configured providers: ${providers.map(p => chalk.cyan(p)).join(', ')}
Default: ${chalk.cyan(config.get('defaultProvider'))} / ${chalk.cyan(config.get('defaultModel'))}`,
    'cyan'
  );

  // Main menu loop
  let running = true;
  let ares: Ares | null = null;

  while (running) {
    const choices = [
      { name: '🚀 Start New Operation', value: 'new' },
    ];

    if (ares) {
      choices.push(
        { name: '📊 View Status', value: 'status' },
        { name: '👤 Spawn Operator', value: 'spawn' },
        { name: '🎯 Add Target', value: 'target' },
        { name: '📋 Create Mission', value: 'mission' },
        { name: '💬 Chat with AI', value: 'chat' },
        { name: '📝 Generate Report', value: 'report' },
        { name: '⏹️  Stop Operation', value: 'stop' },
      );
    }

    choices.push(
      { name: '⚙️  Settings', value: 'settings' },
      { name: '🚪 Exit', value: 'exit' },
    );

    const { action } = await inquirer.prompt([
      {
        type: 'list',
        name: 'action',
        message: ares ? `[${ares.command.name}] What would you like to do?` : 'What would you like to do?',
        choices,
      },
    ]);

    try {
      switch (action) {
        case 'new':
          ares = await startNewOperation();
          break;
        case 'status':
          if (ares) displayStatus(ares);
          break;
        case 'spawn':
          if (ares) await spawnOperator(ares);
          break;
        case 'target':
          if (ares) await addTarget(ares);
          break;
        case 'mission':
          if (ares) await createMission(ares);
          break;
        case 'chat':
          if (ares) await chatWithAI(ares);
          break;
        case 'report':
          if (ares) await generateReport(ares);
          break;
        case 'stop':
          if (ares) {
            ares.command.stop();
            showSuccess('Operation stopped');
            ares = null;
          }
          break;
        case 'settings':
          await openSettings();
          break;
        case 'exit':
          if (ares) {
            const { confirmExit } = await inquirer.prompt([
              {
                type: 'confirm',
                name: 'confirmExit',
                message: 'Operation is running. Are you sure you want to exit?',
                default: false,
              },
            ]);
            if (!confirmExit) continue;
            ares.command.stop();
          }
          running = false;
          break;
      }
    } catch (error) {
      showError(`Error: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  console.log(chalk.gray('\nGoodbye!\n'));
}

async function startNewOperation(): Promise<Ares> {
  const { name, type } = await inquirer.prompt([
    {
      type: 'input',
      name: 'name',
      message: 'Operation name:',
      default: `Operation ${Date.now().toString(36).toUpperCase()}`,
    },
    {
      type: 'list',
      name: 'type',
      message: 'Operation type:',
      choices: [
        { name: 'Auto (use configured defaults)', value: 'auto' },
        { name: 'Stealth (minimal detection)', value: 'stealth' },
        { name: 'Aggressive (maximum speed)', value: 'aggressive' },
        { name: 'Test (mock LLM)', value: 'test' },
      ],
    },
  ]);

  const spinner = ora('Initializing operation...').start();

  let ares: Ares;

  switch (type) {
    case 'stealth':
      ares = createStealthOperation(name);
      break;
    case 'aggressive':
      ares = createAggressiveOperation(name);
      break;
    case 'test':
      ares = createTestAres(name);
      break;
    default:
      ares = createAutoAres(name);
  }

  ares.command.start();
  spinner.succeed(`Operation "${name}" started!`);

  displayStatus(ares);

  return ares;
}

async function spawnOperator(ares: Ares): Promise<void> {
  const archetypes: OperatorArchetype[] = [
    'recon', 'scanner', 'exploiter', 'infiltrator',
    'exfiltrator', 'ghost', 'coordinator', 'analyst',
  ];

  const { archetype, callsign } = await inquirer.prompt([
    {
      type: 'list',
      name: 'archetype',
      message: 'Select operator archetype:',
      choices: archetypes.map(a => ({
        name: `${a.charAt(0).toUpperCase() + a.slice(1)}`,
        value: a,
      })),
    },
    {
      type: 'input',
      name: 'callsign',
      message: 'Operator callsign:',
      default: (answers: { archetype: string }) =>
        `${answers.archetype.charAt(0).toUpperCase() + answers.archetype.slice(1)}-${ares.cell.getAllOperators().length + 1}`,
    },
  ]);

  const operator = ares.command.spawnOperator(callsign, archetype);
  showSuccess(`Operator ${callsign} (${archetype}) spawned!`);
  showInfo(`ID: ${operator.id}`);
}

async function addTarget(ares: Ares): Promise<void> {
  const { address, type, zone } = await inquirer.prompt([
    {
      type: 'input',
      name: 'address',
      message: 'Target address (URL or IP):',
      validate: (input: string) => input.length > 0 || 'Address is required',
    },
    {
      type: 'list',
      name: 'type',
      message: 'Target type:',
      choices: [
        'web_application',
        'api',
        'network',
        'host',
        'database',
        'cloud',
      ],
    },
    {
      type: 'list',
      name: 'zone',
      message: 'Target zone:',
      choices: ['external', 'dmz', 'internal', 'restricted'],
    },
  ]);

  const target = ares.targetEnv.addTarget({
    name: address,
    type,
    zone,
    address,
  });

  showSuccess(`Target "${address}" added!`);
  showInfo(`ID: ${target.id}`);
}

async function createMission(ares: Ares): Promise<void> {
  const { name, objectives } = await inquirer.prompt([
    {
      type: 'input',
      name: 'name',
      message: 'Mission name:',
      default: 'Primary Mission',
    },
    {
      type: 'input',
      name: 'objectives',
      message: 'Objectives (comma-separated):',
      default: 'Enumerate attack surface, Identify vulnerabilities, Document findings',
    },
  ]);

  const mission = ares.mission.createMission({
    name,
    objectives: objectives.split(',').map((o: string) => o.trim()),
  });

  ares.mission.startMission(mission.id);

  showSuccess(`Mission "${name}" created and started!`);
  showInfo(`ID: ${mission.id}`);
}

async function chatWithAI(ares: Ares): Promise<void> {
  showInfo('Chat mode - type "exit" to return to menu\n');

  let chatting = true;

  while (chatting) {
    const { message } = await inquirer.prompt([
      {
        type: 'input',
        name: 'message',
        message: chalk.cyan('You:'),
        validate: (input: string) => input.length > 0 || 'Enter a message',
      },
    ]);

    if (message.toLowerCase() === 'exit') {
      chatting = false;
      continue;
    }

    const spinner = ora('Thinking...').start();

    try {
      const response = await ares.llm.prompt(message);
      spinner.stop();
      console.log(chalk.green('AI:'), response);
      console.log('');
    } catch (error) {
      spinner.fail('Error');
      showError(`${error instanceof Error ? error.message : String(error)}`);
    }
  }
}

async function generateReport(ares: Ares): Promise<void> {
  const mission = ares.mission.getActiveMission();

  if (!mission) {
    // Create a temporary mission for report
    const tempMission = ares.mission.createMission({
      name: 'Ad-hoc Report',
      objectives: ['Generate findings report'],
    });
    ares.mission.startMission(tempMission.id);
  }

  try {
    const report = ares.command.generateReport();
    console.log('');
    console.log(chalk.bold.cyan('═══ ENGAGEMENT REPORT ═══'));
    console.log('');
    console.log(report);
  } catch (error) {
    showWarning('No findings to report yet.');
  }
}

async function openSettings(): Promise<void> {
  const { setting } = await inquirer.prompt([
    {
      type: 'list',
      name: 'setting',
      message: 'Settings:',
      choices: [
        { name: 'View current configuration', value: 'view' },
        { name: 'Change default provider', value: 'provider' },
        { name: 'Change default model', value: 'model' },
        { name: 'Add/update API key', value: 'apikey' },
        { name: 'Back', value: 'back' },
      ],
    },
  ]);

  switch (setting) {
    case 'view': {
      const settings = config.getAll();
      console.log('');
      console.log(chalk.bold('Current Configuration:'));
      console.log(chalk.cyan('  Provider:'), settings.defaultProvider);
      console.log(chalk.cyan('  Model:'), settings.defaultModel);
      console.log(chalk.cyan('  OpenRouter:'), hasApiKey('openrouter') ? chalk.green('configured') : chalk.red('not set'));
      console.log(chalk.cyan('  Venice:'), hasApiKey('venice') ? chalk.green('configured') : chalk.red('not set'));
      console.log(chalk.cyan('  Anthropic:'), hasApiKey('anthropic') ? chalk.green('configured') : chalk.red('not set'));
      console.log(chalk.cyan('  OpenAI:'), hasApiKey('openai') ? chalk.green('configured') : chalk.red('not set'));
      console.log('');
      break;
    }

    case 'provider': {
      const providers = getConfiguredProviders().filter(p => p !== 'mock');
      if (providers.length === 0) {
        showWarning('No API keys configured');
        break;
      }
      const { provider } = await inquirer.prompt([
        {
          type: 'list',
          name: 'provider',
          message: 'Select default provider:',
          choices: providers,
          default: config.get('defaultProvider'),
        },
      ]);
      config.setDefaultProvider(provider);
      showSuccess(`Default provider set to: ${provider}`);
      break;
    }

    case 'model': {
      const currentProvider = config.get('defaultProvider');
      const availableModels = AVAILABLE_MODELS[currentProvider];
      if (!availableModels || availableModels.length === 0) {
        showWarning(`No models available for ${currentProvider}`);
        break;
      }
      const { selectedModel } = await inquirer.prompt([
        {
          type: 'list',
          name: 'selectedModel',
          message: 'Select default model:',
          choices: availableModels.map(m => ({
            name: `${m.name} (${m.id}) - ${m.contextWindow.toLocaleString()} ctx`,
            value: m.id,
          })),
          default: config.get('defaultModel'),
        },
      ]);
      config.setDefaultModel(currentProvider, selectedModel);
      showSuccess(`Default model set to: ${selectedModel}`);
      break;
    }

    case 'apikey': {
      const { keyProvider } = await inquirer.prompt([
        {
          type: 'list',
          name: 'keyProvider',
          message: 'Which provider?',
          choices: ['openrouter', 'venice', 'anthropic', 'openai'],
        },
      ]);
      const { apiKey } = await inquirer.prompt([
        {
          type: 'password',
          name: 'apiKey',
          message: `Enter ${keyProvider} API key:`,
          mask: '*',
        },
      ]);
      if (apiKey) {
        setApiKey(keyProvider, apiKey);
        showSuccess(`${keyProvider} API key saved!`);
      }
      break;
    }
  }
}

// =============================================================================
// CLI COMMANDS
// =============================================================================

const program = new Command();

program
  .name('ares')
  .description('ARES - Tactical Execution Multi-agent Platform for Elite Security Testing')
  .version('1.0.0');

program
  .command('interactive', { isDefault: true })
  .description('Start interactive mode')
  .action(interactiveMode);

program
  .command('setup')
  .description('Run the setup wizard')
  .action(async () => {
    const { execSync } = await import('child_process');
    try {
      execSync('npx tsx src/setup.ts', { stdio: 'inherit', cwd: process.cwd() });
    } catch {
      // Setup script handles its own errors
    }
  });

program
  .command('status')
  .description('Show current configuration status')
  .action(() => {
    showBanner();
    const settings = config.getAll();

    console.log(chalk.bold('Configuration Status:\n'));

    const table = new Table({
      style: { head: [], border: [] },
    });

    table.push(
      [chalk.cyan('Default Provider'), settings.defaultProvider],
      [chalk.cyan('Default Model'), settings.defaultModel],
      [chalk.cyan('OpenRouter API Key'), hasApiKey('openrouter') ? chalk.green('✓ Configured') : chalk.red('✗ Not set')],
      [chalk.cyan('Venice API Key'), hasApiKey('venice') ? chalk.green('✓ Configured') : chalk.red('✗ Not set')],
      [chalk.cyan('Anthropic API Key'), hasApiKey('anthropic') ? chalk.green('✓ Configured') : chalk.red('✗ Not set')],
      [chalk.cyan('OpenAI API Key'), hasApiKey('openai') ? chalk.green('✓ Configured') : chalk.red('✗ Not set')],
      [chalk.cyan('Config Path'), config.getConfigPath()],
    );

    console.log(table.toString());
    console.log('');
  });

program
  .command('test')
  .description('Test the LLM connection')
  .action(async () => {
    showBanner();

    const provider = config.get('defaultProvider');

    if (!hasApiKey(provider as any)) {
      showError(`No API key configured for ${provider}`);
      showInfo('Run "npx ares setup" to configure API keys');
      return;
    }

    const spinner = ora(`Testing connection to ${provider}...`).start();

    try {
      const llm = new LLMBackbone(config.getLLMConfig());
      const response = await llm.prompt('Say "Connection successful!" and nothing else.');

      spinner.succeed('Connection successful!');
      console.log('');
      console.log(chalk.cyan('Response:'), response);
      console.log('');
    } catch (error) {
      spinner.fail('Connection failed');
      showError(`${error instanceof Error ? error.message : String(error)}`);
    }
  });

program
  .command('models')
  .description('List available models')
  .action(() => {
    showBanner();

    const provider = config.get('defaultProvider');
    const models = AVAILABLE_MODELS[provider];

    console.log(chalk.bold(`Available models for ${provider}:\n`));

    const table = new Table({
      head: [chalk.cyan('Model ID'), chalk.cyan('Name'), chalk.cyan('Context')],
      style: { head: [], border: [] },
    });

    for (const model of models) {
      table.push([
        model.id,
        model.name,
        `${model.contextWindow.toLocaleString()} tokens`,
      ]);
    }

    console.log(table.toString());
    console.log('');
  });

// Run CLI
program.parse();
