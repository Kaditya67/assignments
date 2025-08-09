import { useState } from "react";
import { Button } from "@mui/material";
import { authorizeHubspot, getHubspotCredentials } from "./hubspot";

export function HubspotIntegration({ user, org, integrationParams, setIntegrationParams }) {
  const [connected, setConnected] = useState(false);

  const handleConnect = async () => {
    await authorizeHubspot(user, org);
  };

  const handleSync = async () => {
    const credentials = await getHubspotCredentials(user, org);
    setIntegrationParams({
      type: "Hubspot",
      credentials,
    });
    setConnected(true);
  };

  return (
    <div>
      <Button variant="contained" onClick={handleConnect} sx={{ mt: 2 }}>
        Connect HubSpot
      </Button>
      <Button variant="outlined" onClick={handleSync} sx={{ mt: 2, ml: 2 }}>
        Sync HubSpot Data
      </Button>
      {connected && <div>Credentials fetched and ready!</div>}
    </div>
  );
}
