FROM node:22-alpine
WORKDIR /app
COPY agent.mjs analysis.mjs ./
ENV AGENT_MAX_STEPS=24
USER node
ENTRYPOINT ["node", "/app/agent.mjs"]
