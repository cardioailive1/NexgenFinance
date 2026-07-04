'use strict';
const Anthropic = require('@anthropic-ai/sdk');
const config    = require('../config');
const logger    = require('../utils/logger');

const client = new Anthropic({ apiKey: config.anthropic.apiKey });

const TRADING_SYSTEM = `You are NexGen Trading Agent, an elite AI market analyst and systematic trader built by Corverxis Technologies, powered by NexGen Ultra. You have access to a web search tool — ALWAYS use it to fetch current, live market prices and data before producing any analysis. Never rely on training data alone for prices or market conditions. You produce professional, actionable trade intelligence covering financial markets (equities, indices), currency markets (FX pairs, DXY), and commodity markets (energy, metals, agriculture, crypto).

After your complete report, on a new line write exactly: ##XAI## then a new line, then "**Data sources & methodology**" with 2-3 sentences on what you searched and how you built the analysis, then a blank line, then "**Important disclaimer**" with 1-2 sentences that this is AI-generated analysis for educational purposes only and not financial advice — all trades involve risk of loss and users should consult a licensed financial advisor, then ##XAI## again on its own line.`;

const FINANCE_SYSTEM = `You are NexGen Finance, an AI financial analyst built by Corverxis Technologies, powered by NexGen Ultra. You produce professional-grade financial statements, accounting documents, audit materials and market analysis. Always use proper accounting terminology, correctly formatted numbers (commas, parentheses for negatives, $ signs), and clean markdown tables for financial data. Be precise with calculations — numbers must foot and cross-check correctly.

After your complete report, on a new line write exactly: ##XAI## then a new line, then "**How I approached this**" with 2-3 sentences on your methodology and what assumptions you made, then a blank line, then "**Confidence & verification**" with 1-2 sentences on what should be verified by a licensed CPA/CFA/auditor before relying on this for real decisions, then ##XAI## again on its own line. Never put the XAI block before or in the middle of the report — only at the very end.`;

/**
 * Generate a report via Claude API.
 * @param {object} opts
 * @param {string} opts.module   - 'trading' | other
 * @param {string} opts.prompt   - user prompt
 * @returns {{ text: string, tokenCount: number, model: string }}
 */
async function generateReport({ module: mod, prompt }) {
  const isTrading = mod === 'TRADING';
  const system    = isTrading ? TRADING_SYSTEM : FINANCE_SYSTEM;

  const body = {
    model:      config.anthropic.model,
    max_tokens: 4096,
    system,
    messages:   [{ role: 'user', content: prompt }],
  };

  if (isTrading) {
    body.tools = [{ type: 'web_search_20250305', name: 'web_search' }];
  }

  logger.info('Anthropic request', { module: mod, model: body.model, isTrading });

  const response = await client.messages.create(body);

  // Collect all text blocks (tool_use responses return multiple content blocks)
  const text = response.content
    .filter((b) => b.type === 'text')
    .map((b) => b.text)
    .join('');

  const tokenCount = (response.usage?.input_tokens || 0) + (response.usage?.output_tokens || 0);

  logger.info('Anthropic response', { tokenCount, stopReason: response.stop_reason });

  return { text, tokenCount, model: response.model };
}

module.exports = { generateReport };
