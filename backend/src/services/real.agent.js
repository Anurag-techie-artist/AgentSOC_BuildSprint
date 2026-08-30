const { execFile } = require('child_process');
const path = require('path');
const fs = require('fs');
const os = require('os');

class RealAgent {
  constructor() {
    this.repoRoot = path.resolve(__dirname, '../../../');
    this.runnerPath = path.resolve(this.repoRoot, 'agent/src/runner.py');
    this.pythonCmd = process.env.PYTHON_PATH || 'python';
  }

  /**
   * Runs the real Python AI Agent via agent/src/runner.py.
   * @param {Object} agentInput - Validated AgentInput object.
   * @returns {Promise<Object>} Validated AgentOutput object returned by Python agent.
   */
  async runInvestigation(agentInput) {
    const tmpDir = os.tmpdir();
    const tempInputFile = path.join(
      tmpDir,
      `agent_input_${Date.now()}_${Math.random().toString(36).substring(2, 9)}.json`
    );

    fs.writeFileSync(tempInputFile, JSON.stringify(agentInput, null, 2), 'utf8');

    return new Promise((resolve, reject) => {
      execFile(
        this.pythonCmd,
        [this.runnerPath, tempInputFile],
        { cwd: this.repoRoot, env: { ...process.env } },
        (error, stdout, stderr) => {
          // Always clean up the temporary file
          try {
            if (fs.existsSync(tempInputFile)) {
              fs.unlinkSync(tempInputFile);
            }
          } catch (cleanupError) {
            // Ignore cleanup errors
          }

          if (error) {
            return reject(new Error(`Real Agent execution failed: ${stderr || error.message || stdout}`));
          }

          const marker = '=== Investigation Completed Successfully ===';
          const markerIdx = stdout.indexOf(marker);

          if (markerIdx === -1) {
            return reject(new Error(`Real Agent output missing completion marker. Output: ${stdout}`));
          }

          const jsonText = stdout.substring(markerIdx + marker.length).trim();
          try {
            const output = JSON.parse(jsonText);
            resolve(output);
          } catch (parseError) {
            reject(new Error(`Failed to parse AgentOutput JSON: ${parseError.message}. Output snippet: ${jsonText}`));
          }
        }
      );
    });
  }
}

module.exports = new RealAgent();
