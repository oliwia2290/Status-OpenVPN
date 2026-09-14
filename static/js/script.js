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

    const last_ftp_date = new Date(r.last_ftp_data);
    const cn_now = new Date();
    const ftp_now = new Date();

    let old = false;

    if (r.last_seen) {
       const last_seen_date = new Date(r.last_seen);
       last_seen_date.setDate(last_seen_date.getDate()-1);

       old = last_ftp_date <= last_seen_date;
    } else {
       ftp_now.setDate(ftp_now.getDate()-1);

       old = last_ftp_date <= ftp_now;
    }

    const cn_end_date = new Date(r.cn_end_date);
    cn_end_date.setDate(cn_end_date.getDate()-7);
    const short_life = cn_now >= cn_end_date

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
      <td class="${short_life ? 'short_life_color' : ''}">${r.cn_end_date}</td>
      <td class="${old ? 'last_ftp_data_color' : ''}">${r.last_ftp_data}</td>
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
