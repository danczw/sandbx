// Shared interactive components for every lesson.
//
// Quiz:
//   <div class="quiz">
//     <fieldset class="q">
//       <legend>Question?</legend>
//       <label class="opt"><input type="radio"> Answer</label>
//       <label class="opt" data-correct><input type="radio"> Answer</label>
//       <div class="why">Explanation shown after answering.</div>
//     </fieldset>
//     <p class="score"></p>
//   </div>
//   Options are shuffled on load, so a retake does not reward remembering positions.
//
// Recall:
//   <div class="recall" data-key="unique-storage-key">
//     <textarea placeholder="..."></textarea>
//     <button data-reveal>Check against the model answer</button>
//     <div class="checklist"><label><input type="checkbox"> Point</label>...</div>
//     <div class="model">Model answer.</div>
//   </div>
//   The draft is kept in localStorage when available; the page works without it.
//
// Order (put steps in sequence):
//   <div class="order">
//     <ol class="pool"><li>First step</li><li>Second step</li>...</ol>
//     <ol class="placed"></ol>
//     <p class="verdict"></p>
//   </div>
//   Author the steps in the correct order; they are shuffled on load. Clicking a step
//   places it; a wrong pick is flagged at once and stays in the pool.
//
// Classify (sort items into fixed categories):
//   <div class="classify" data-cats="Landlock|seccomp|Namespace|Other">
//     <ol>
//       <li data-answer="Landlock" data-why="Explanation.">Item text</li>
//     </ol>
//     <p class="score"></p>
//   </div>
//   Every item gets the same buttons in the same order, so no option's wording gives the
//   answer away. Items are shuffled on load; one pick per item, judged at once.

(function () {
  function shuffle(nodes) {
    for (let i = nodes.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [nodes[i], nodes[j]] = [nodes[j], nodes[i]];
    }
    return nodes;
  }

  function initQuiz(quiz) {
    const questions = Array.from(quiz.querySelectorAll(".q"));
    const score = quiz.querySelector(".score");
    let answered = 0;
    let right = 0;

    questions.forEach((q, qi) => {
      const opts = Array.from(q.querySelectorAll(".opt"));
      const anchor = q.querySelector(".why");
      shuffle(opts).forEach((o) => q.insertBefore(o, anchor));
      opts.forEach((o) => {
        const input = o.querySelector("input");
        input.name = "q" + qi + "-" + Math.random().toString(36).slice(2);
        input.addEventListener("change", () => {
          if (q.classList.contains("done")) return;
          q.classList.add("done");
          const correct = o.hasAttribute("data-correct");
          o.classList.add(correct ? "right" : "wrong");
          if (!correct) q.querySelector("[data-correct]").classList.add("right");
          opts.forEach((x) => (x.querySelector("input").disabled = true));
          answered++;
          if (correct) right++;
          if (score) {
            score.textContent =
              answered === questions.length
                ? `${right} of ${questions.length} correct. Retake tomorrow morning: the options reshuffle.`
                : `${right} of ${answered} so far.`;
          }
        });
      });
    });
  }

  function store(key, value) {
    try {
      if (value === undefined) return localStorage.getItem(key);
      localStorage.setItem(key, value);
    } catch (_) {
      return null;
    }
  }

  function initRecall(box) {
    const key = "teach:" + (box.dataset.key || "");
    const area = box.querySelector("textarea");
    const saved = store(key);
    if (area && saved) area.value = saved;
    if (area) area.addEventListener("input", () => store(key, area.value));
    const reveal = box.querySelector("[data-reveal]");
    if (reveal) {
      reveal.addEventListener("click", () => {
        box.classList.add("revealed");
        reveal.remove();
      });
    }
  }

  function initOrder(box) {
    const pool = box.querySelector(".pool");
    const placed = box.querySelector(".placed");
    const verdict = box.querySelector(".verdict");
    const steps = Array.from(pool.children);
    steps.forEach((li, i) => (li.dataset.pos = i));
    shuffle(steps.slice()).forEach((li) => pool.appendChild(li));
    let next = 0;
    let misses = 0;
    steps.forEach((li) => {
      li.addEventListener("click", () => {
        if (li.parentElement !== pool) return;
        if (Number(li.dataset.pos) === next) {
          li.classList.remove("miss");
          placed.appendChild(li);
          next++;
          if (next === steps.length && verdict) {
            verdict.textContent =
              misses === 0
                ? "All in order, first try."
                : `In order, with ${misses} wrong pick${misses === 1 ? "" : "s"}. Try it again tomorrow.`;
          }
        } else {
          misses++;
          li.classList.add("miss");
          setTimeout(() => li.classList.remove("miss"), 900);
        }
      });
    });
  }

  function initClassify(box) {
    const cats = (box.dataset.cats || "").split("|");
    const list = box.querySelector("ol");
    const score = box.querySelector(".score");
    const items = Array.from(list.children);
    shuffle(items.slice()).forEach((li) => list.appendChild(li));
    let answered = 0;
    let right = 0;
    items.forEach((li) => {
      const row = document.createElement("div");
      row.className = "cats";
      const why = document.createElement("div");
      why.className = "why";
      why.innerHTML = li.dataset.why || "";
      cats.forEach((cat) => {
        const b = document.createElement("button");
        b.type = "button";
        b.className = "ghost";
        b.textContent = cat;
        b.addEventListener("click", () => {
          if (li.classList.contains("done")) return;
          li.classList.add("done");
          const ok = cat === li.dataset.answer;
          b.classList.add(ok ? "right" : "wrong");
          row.querySelectorAll("button").forEach((x) => {
            x.disabled = true;
            if (x.textContent === li.dataset.answer) x.classList.add("right");
          });
          answered++;
          if (ok) right++;
          if (score) {
            score.textContent =
              answered === items.length
                ? `${right} of ${items.length} sorted correctly.`
                : `${right} of ${answered} so far.`;
          }
        });
        row.appendChild(b);
      });
      li.appendChild(row);
      li.appendChild(why);
    });
  }

  document.querySelectorAll(".quiz").forEach(initQuiz);
  document.querySelectorAll(".recall").forEach(initRecall);
  document.querySelectorAll(".order").forEach(initOrder);
  document.querySelectorAll(".classify").forEach(initClassify);
})();
