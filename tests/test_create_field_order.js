const assert = require("node:assert/strict");

const {
  createFieldOrder,
  reorderCreateFields,
} = require("../src/blockwart/ui/static/create_field_order.js");

const rendered = [
  "runbook_status",
  "in_scope",
  "review_after",
  "related_projects",
  "project_status",
  "decision_status",
  "docs",
];

assert.deepEqual(
  createFieldOrder([
    { key: "project_status" },
    { key: "in_scope" },
    { key: "review_after" },
    { key: "related_projects" },
  ], rendered),
  [
    "project_status",
    "in_scope",
    "review_after",
    "related_projects",
    "runbook_status",
    "decision_status",
    "docs",
  ],
);

const overriddenKeys = [
  "kind",
  "object_id",
  "primary_name",
  "status",
  "summary",
  "category",
  "project_status",
];
const overriddenFields = new Map(overriddenKeys.map((key) => [key, { key }]));
const overriddenAnchor = { key: "anchor" };
const overriddenContainer = {
  children: [...overriddenFields.values(), overriddenAnchor],
  insertBefore(field, before) {
    this.children.splice(this.children.indexOf(field), 1);
    this.children.splice(this.children.indexOf(before), 0, field);
  },
};

reorderCreateFields(overriddenContainer, overriddenAnchor, overriddenFields, [
  { key: "summary" },
  { key: "kind" },
  { key: "object_id" },
  { key: "primary_name" },
  { key: "category" },
  { key: "project_status" },
  { key: "status" },
]);
assert.deepEqual(
  overriddenContainer.children.map((field) => field.key),
  [
    "summary",
    "kind",
    "object_id",
    "primary_name",
    "category",
    "project_status",
    "status",
    "anchor",
  ],
);

const fields = new Map(rendered.map((key) => [key, { key }]));
const anchor = { key: "anchor" };
const container = {
  children: [...fields.values(), anchor],
  insertBefore(field, before) {
    this.children.splice(this.children.indexOf(field), 1);
    this.children.splice(this.children.indexOf(before), 0, field);
  },
};

reorderCreateFields(container, anchor, fields, [
  { key: "decision_status" },
  { key: "review_after" },
  { key: "related_projects" },
  { key: "docs" },
]);
assert.deepEqual(
  container.children.map((field) => field.key),
  [
    "decision_status",
    "review_after",
    "related_projects",
    "docs",
    "runbook_status",
    "in_scope",
    "project_status",
    "anchor",
  ],
);

assert.deepEqual(
  createFieldOrder([
    { key: "decision_status" },
    { key: "review_after" },
    { key: "related_projects" },
    { key: "docs" },
  ], rendered),
  [
    "decision_status",
    "review_after",
    "related_projects",
    "docs",
    "runbook_status",
    "in_scope",
    "project_status",
  ],
);
