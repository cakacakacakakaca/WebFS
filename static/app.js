(function(){
  function qs(sel, el=document){ return el.querySelector(sel); }
  function clamp(n, a, b){ return Math.max(a, Math.min(b, n)); }

  function initImageViewer(){
    const root = qs(".fsviewer[data-page='image']");
    if(!root) return;

    const images = JSON.parse(root.getAttribute("data-images") || "[]");
    let idx = parseInt(root.getAttribute("data-index") || "0", 10);
    idx = clamp(idx, 0, Math.max(0, images.length - 1));

    const img = qs("#viewerImg");
    const btnPrev = qs("#btnPrev");
    const btnNext = qs("#btnNext");
    const stage = qs("#viewerStage");
    const nameEl = qs("#fsName");
    const countEl = qs("#fsCount");

    // iOS/部分浏览器：进一步避免回弹
    document.documentElement.style.overscrollBehavior = "none";
    document.body.style.overscrollBehavior = "none";

    function setMeta(p){
      if(nameEl){
        const base = decodeURIComponent(p.split("/").pop() || "");
        nameEl.textContent = base || "图片";
      }
      if(countEl){
        countEl.textContent = images.length ? `${idx + 1} / ${images.length}` : "";
      }
    }

    function setImage(i){
      if(images.length === 0) return;
      idx = clamp(i, 0, images.length - 1);
      const p = images[idx];

      // 直接替换 src（raw 支持 Range，加载也稳）
      img.src = "/raw/" + encodeURI(p);

      // 更新地址（不刷新）便于复制分享
      const newUrl = "/open/" + encodeURI(p);
      window.history.replaceState({}, "", newUrl);

      setMeta(p);
    }

    function prev(){ if(idx > 0) setImage(idx - 1); }
    function next(){ if(idx < images.length - 1) setImage(idx + 1); }

    if(btnPrev) btnPrev.addEventListener("click", prev);
    if(btnNext) btnNext.addEventListener("click", next);

    // 桌面：键盘左右
    window.addEventListener("keydown", (e)=>{
      if(e.key === "ArrowLeft") { e.preventDefault(); prev(); }
      if(e.key === "ArrowRight") { e.preventDefault(); next(); }
    });

    // 移动端：左右滑切换（自然，不触发下拉刷新）
    let startX = 0, startY = 0, active = false;

    stage.addEventListener("touchstart", (e)=>{
      if(!e.touches || e.touches.length !== 1) return;
      active = true;
      startX = e.touches[0].clientX;
      startY = e.touches[0].clientY;
    }, {passive:true});

    // 关键：touchmove 必须 passive:false 才能 preventDefault 阻止页面滚动/下拉刷新
    stage.addEventListener("touchmove", (e)=>{
      if(!active) return;

      const t = e.touches[0];
      const dx = t.clientX - startX;
      const dy = t.clientY - startY;

      // 只要手指在画面上移动，就阻止浏览器默认滚动
      // （否则会出现页面跟着动、或触发下拉刷新）
      e.preventDefault();

      // 不在 move 阶段切换，避免抖动；在 touchend 决定
    }, {passive:false});

    stage.addEventListener("touchend", (e)=>{
      if(!active) return;
      active = false;

      const t = (e.changedTouches && e.changedTouches[0]) ? e.changedTouches[0] : null;
      if(!t) return;

      const dx = t.clientX - startX;
      const dy = t.clientY - startY;

      // 横向滑动阈值：60px；且要求横向明显大于纵向，避免误触
      if(Math.abs(dx) > 60 && Math.abs(dx) > Math.abs(dy) * 1.2){
        if(dx < 0) next(); // 左滑 -> 下一张
        else prev();       // 右滑 -> 上一张
      }
    }, {passive:true});

    // 额外：单击左右区域切换（对不爱滑动的人更友好）
    stage.addEventListener("click", (e)=>{
      const rect = stage.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const r = x / rect.width;
      if(r < 0.33) prev();
      else if(r > 0.67) next();
    });

    // 初始化
    setImage(idx);
  }

  document.addEventListener("DOMContentLoaded", ()=>{
    initImageViewer();
  });
})();