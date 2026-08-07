import { Sandbox } from '@vercel/sandbox'

// Fixed location inside the sandbox where the agent instruction is written
const INSTRUCTION_FILE = '/tmp/ares-agent-instruction.txt'

/**
 * Write the agent instruction to a file inside the sandbox (base64-encoded so
 * no prompt content ever appears in a shell command string). Returns a shell
 * fragment that expands to the instruction as a single argument; command
 * substitution output is not re-scanned for quotes, so prompt content cannot
 * break out of the surrounding double quotes.
 */
export async function writeInstructionFile(sandbox: Sandbox, instruction: string): Promise<string> {
  const encoded = Buffer.from(instruction, 'utf-8').toString('base64')
  const result = await sandbox.runCommand({
    cmd: 'sh',
    args: ['-c', `echo '${encoded}' | base64 -d > ${INSTRUCTION_FILE}`],
  })

  if (result.exitCode !== 0) {
    throw new Error('Failed to write instruction file to sandbox')
  }

  return `"$(cat ${INSTRUCTION_FILE})"`
}
