// Attendance Overview: section-by-section totals.
// Loaded after the portal's existing script. No database changes required.
renderSummary = function () {
  if (!leader()) return;
  const id = Number(document.getElementById('summary-event').value);
  const event = events.find(e => e.id === id);
  const target = document.getElementById('summary-content');
  if (!event) {
    target.innerHTML = '<p class="muted">Choose an event.</p>';
    return;
  }
  // Exclude members who have not yet confirmed their instrument group.
  // Their legacy section_id may still point to Baritone & Tenor Horn.
  const active = members.filter(m =>
    m.active && m.section_confirmed !== 0 &&
    (admin() || m.section_id === user.section_id)
  );
  const rows = active.map(m => ({
    m,
    response: attendance.find(a => a.event_id === id && a.member_id === m.id)?.response
  }));
  const groupList = admin()
    ? [...sections, ...(active.some(m => !sections.some(s => String(s.id) === String(m.section_id))) ? [{id:null,name:'Unassigned'}] : [])]
    : sections.filter(s => String(s.id) === String(user.section_id));
  const count = (items, value) => items.filter(r => r.response === value).length;
  const sectionRows = groupList.map(s => {
    const group = rows.filter(r => s.id === null
      ? !sections.some(x => String(x.id) === String(r.m.section_id))
      : String(r.m.section_id) === String(s.id));
    return `<tr><td>${esc(s.name)}</td><td>${count(group,'yes')}</td><td>${count(group,'no')}</td><td>${count(group,'maybe')}</td><td>${count(group,undefined)}</td></tr>`;
  }).join('');
  const totals = `<tr><th scope="row">Total</th><th>${count(rows,'yes')}</th><th>${count(rows,'no')}</th><th>${count(rows,'maybe')}</th><th>${count(rows,undefined)}</th></tr>`;
  const table = `<h3>Attendance by instrument group</h3>
    <div class="tablewrap"><table>
    <thead><tr><th>Instrument group</th><th>Attending</th><th>Not attending</th><th>Unsure</th><th>No response</th></tr></thead>
    <tbody>${sectionRows}${totals}</tbody></table></div>`;
  const roster = `<h3>Individual responses</h3><div class="tablewrap"><table>
    <thead><tr><th>Member</th><th>Response</th><th>Actual Attendance</th></tr></thead><tbody>${rows.map(({m,response}) =>
      `<tr><td>${esc(m.display_name)}</td><td><select data-attend-member="${m.id}">
      <option value="" ${!response?'selected':''}>No response</option>
      ${['yes','no','maybe'].map(v => `<option value="${v}" ${response===v?'selected':''}>${responseLabel[v]}</option>`).join('')}
      </select></td>
<td>
  <select data-verify-member="${m.id}">
    <option value="" ${!attendanceVerifications.some(v =>
      Number(v.event_id) === id &&
      Number(v.member_id) === Number(m.id)
    ) ? 'selected' : ''}>Not Verified</option>

    <option value="present" ${attendanceVerifications.some(v =>
      Number(v.event_id) === id &&
      Number(v.member_id) === Number(m.id) &&
      v.status === 'present'
    ) ? 'selected' : ''}>Confirmed Present</option>

    <option value="no_show" ${attendanceVerifications.some(v =>
      Number(v.event_id) === id &&
      Number(v.member_id) === Number(m.id) &&
      v.status === 'no_show'
    ) ? 'selected' : ''}>No Show</option>
  </select>
</td></tr>`).join('')}</tbody></table></div>`;
  target.innerHTML = table + roster;
  target.querySelectorAll('[data-attend-member]').forEach(el => el.onchange = async () => {
    if (!el.value) { renderSummary(); return; }
    try {
      await send('/attendance', {
        event_id:id,
        member_id:Number(el.dataset.attendMember),
        response:el.value
      });
      await loadAttendance();
      renderSummary();
    } catch(e) {
      document.getElementById('notice').textContent = e.message;
      renderSummary();
    }
  });
   target.querySelectorAll('[data-verify-member]').forEach(el => {
    el.onchange = async () => {
      const status = el.value;

      if (!status) {
        document.getElementById('notice').textContent =
          'Clearing a verification is not available yet.';
        renderSummary();
        return;
      }

      el.disabled = true;

      try {
        await send('/attendance/verification', {
          event_id: id,
          member_id: Number(el.dataset.verifyMember),
          status
        });

        await loadAttendance();
        renderSummary();

        document.getElementById('notice').textContent =
          'Attendance verification saved.';

      } catch (e) {
        document.getElementById('notice').textContent = e.message;
        renderSummary();
      }
    };
  }); };
