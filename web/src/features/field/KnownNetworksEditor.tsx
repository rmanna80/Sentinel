import { Button, Group, Stack, TagsInput, Text } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { useEffect, useState } from "react";
import { errorMessage } from "../../api/client";
import { ErrorState, Loading, Panel } from "../../components/Page";
import { useKnownNetworks, useSaveKnownNetworks } from "./api";

/**
 * Edit the SSIDs and BSSIDs you own, so Sentinel knows which observed networks are yours. A BSSID must be a
 * MAC address; a bad one comes back from the server as a 422, whose message is shown inline.
 */
export function KnownNetworksEditor() {
  const known = useKnownNetworks();
  const save = useSaveKnownNetworks();
  const [ssids, setSsids] = useState<string[]>([]);
  const [bssids, setBssids] = useState<string[]>([]);

  useEffect(() => {
    if (known.data) {
      setSsids(known.data.own_ssids ?? []);
      setBssids(known.data.own_bssids ?? []);
    }
  }, [known.data]);

  if (known.isPending) return <Loading label="Loading your networks" />;
  if (known.isError) return <ErrorState error={known.error} onRetry={() => void known.refetch()} />;

  return (
    <Panel
      title="Known networks"
      description="The SSIDs and BSSIDs you own. Everything in a survey is compared against these, so an access point that imitates one of your SSIDs from an unknown BSSID can be flagged as a rogue suspect."
    >
      <Stack gap="md">
        <TagsInput
          label="Your SSIDs"
          description="Network names you own. Press Enter after each."
          placeholder="e.g. Acme-Office"
          value={ssids}
          onChange={setSsids}
          clearable
        />
        <TagsInput
          label="Your BSSIDs"
          description="Access-point MAC addresses you own, like AA:BB:CC:DD:EE:FF. Press Enter after each."
          placeholder="AA:BB:CC:DD:EE:FF"
          value={bssids}
          onChange={setBssids}
          clearable
        />
        {save.isError ? (
          <Text size="sm" c="red" role="alert">
            {errorMessage(save.error)}
          </Text>
        ) : null}
        <Group justify="flex-end">
          <Button
            loading={save.isPending}
            onClick={() =>
              save.mutate(
                { own_ssids: ssids, own_bssids: bssids },
                {
                  onSuccess: () => notifications.show({ message: "Known networks saved" }),
                },
              )
            }
          >
            Save networks
          </Button>
        </Group>
      </Stack>
    </Panel>
  );
}
