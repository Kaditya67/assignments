export async function authorizeHubspot(user_id, org_id) {
  const formData = new FormData();
  formData.append("user_id", user_id);
  formData.append("org_id", org_id);
  const res = await fetch("http://localhost:8000/integrations/hubspot/authorize", {
    method: "POST",
    body: formData,
  });
  let url = await res.text();
  url = url.replace(/^"|"$/g, '');
  window.open(url, "_blank", "width=500,height=700");
}

export async function getHubspotCredentials(user_id, org_id) {
  const formData = new FormData();
  formData.append("user_id", user_id);
  formData.append("org_id", org_id);
  const res = await fetch("http://localhost:8000/integrations/hubspot/credentials", {
    method: "POST",
    body: formData,
  });
  return await res.json();
}

export async function loadHubspotItems(credentials) {
  const formData = new FormData();
  formData.append("credentials", JSON.stringify(credentials));
  const res = await fetch("http://localhost:8000/integrations/hubspot/get_hubspot_items", {
    method: "POST",
    body: formData,
  });
  return await res.json();
}
