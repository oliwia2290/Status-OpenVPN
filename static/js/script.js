const evt = new EventSource("/events");
const tbl = document.getElementById("tbl");
const controls = document.getElementById("controls");

const selected = new Set();

tbl.addEventListener("change", e => {
  if (e.target.classList.contains("select-client")) {
    e.target.checked
      ? selected.add(e.target.value)
      : selected.delete(e.target.value);
  }
});

evt.onmessage = ({ data }) => {
  const { rows, cn_permissions } = JSON.parse(data);
  const is_admin_r = cn_permissions[0]
  const is_admin_b = cn_permissions[1]

  tbl.innerHTML = rows.map(r => {
    if (r.empty) {
       return `
       <tr class="empty-row">
          <td></td>
          <td></td>
          <td></td>
          <td></td>
          <td></td>
          <td></td>
          <td></td>
          <td></td>
          <td></td>
          <td></td>
       </tr>`;
    }

    return `
    <tr class="${r.is_degraded ? 'is_degraded' : (r.real_ip ? 'active' : 'inactive')}">
      <td></td>
      <td>
         <input type="checkbox" class="select-client" value="${r.key}" ${selected.has(r.key) ? 'checked' : ''}>
      </td>
      <td>${r.name}</td>
      <td>${r.vpn_ip}</td>
      <td>${r.real_ip}</td>
      <td>${r.mb_received}</td>
      <td>${r.mb_sent}</td>
      <td>${r.connected_since}</td>
      <td>${r.last_seen}</td>
      <td>${r.cn_end_date}</td>
      <td class='status-color'>${r.is_blocked ? (r.real_ip ? 'RESTART INSTANCE TO BLOCK NOW' : 'BLOCKED') : ''}</td>
    </tr>`;
  }).join("");

   if (controls) {
      controls.innerHTML = `
         <button class="restart" onclick="blockSelected()" ${is_admin_b ? "" : "disabled"}>Toggle Block</button>
         <button class="restart" onclick="restart()" ${is_admin_r ? "" : "disabled"}>Restart Instance</button>
      `;
   }
};

const post = (url, body) =>
   fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: body && JSON.stringify(body)
   });

const blockSelected = () => {
   if (!selected.size) return;

   post("/block", {
      keys: [...selected]
   });

   selected.clear();
};

const restart = () => post("/restart");
