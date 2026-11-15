// Starts the locally vendored Swagger UI (static/vendor/swagger-ui) against this server's
// OpenAPI document. Nothing is loaded from a CDN.
window.SwaggerUIBundle({
  url: "/openapi.json",
  dom_id: "#swagger-ui",
  deepLinking: true,
  presets: [window.SwaggerUIBundle.presets.apis],
  layout: "BaseLayout",
});
