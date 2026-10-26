import { Group, Pagination, Select, Text } from "@mantine/core";

export function Pager({
  total,
  limit,
  offset,
  onChange,
  pageSizes = [25, 50, 100],
}: {
  total: number;
  limit: number;
  offset: number;
  onChange: (next: { limit: number; offset: number }) => void;
  pageSizes?: number[];
}) {
  const pages = Math.max(1, Math.ceil(total / limit));
  const page = Math.floor(offset / limit) + 1;
  const from = total === 0 ? 0 : offset + 1;
  const to = Math.min(total, offset + limit);
  return (
    <Group justify="space-between" gap="sm" px="md" py="sm" wrap="wrap">
      <Text size="xs" c="dimmed" className="sn-num">
        {total === 0 ? "No results" : `${from.toLocaleString()}–${to.toLocaleString()} of ${total.toLocaleString()}`}
      </Text>
      <Group gap="sm">
        <Select
          aria-label="Rows per page"
          size="xs"
          w={88}
          data={pageSizes.map((n) => ({ value: String(n), label: `${n} rows` }))}
          value={String(limit)}
          onChange={(v) => onChange({ limit: Number(v ?? limit), offset: 0 })}
        />
        <Pagination
          size="sm"
          total={pages}
          value={page}
          onChange={(p) => onChange({ limit, offset: (p - 1) * limit })}
          getControlProps={(control) => ({ "aria-label": `${control} page` })}
          siblings={1}
          boundaries={1}
        />
      </Group>
    </Group>
  );
}
