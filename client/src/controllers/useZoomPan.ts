import { useRef, useState, type WheelEvent, type MouseEvent } from "react";

const MIN_SCALE = 0.4;
const MAX_SCALE = 1.5;
const SCALE_STEP = 0.1;

export function useZoomPan() {
  const [scale, setScale] = useState(1);
  const [offset, setOffset] = useState({ x: 0, y: 0 });
  const dragState = useRef<{ startX: number; startY: number; originX: number; originY: number } | null>(
    null
  );

  function clampScale(value: number) {
    return Math.min(MAX_SCALE, Math.max(MIN_SCALE, value));
  }

  function zoomIn() {
    setScale((current) => clampScale(current + SCALE_STEP));
  }

  function zoomOut() {
    setScale((current) => clampScale(current - SCALE_STEP));
  }

  function reset() {
    setScale(1);
    setOffset({ x: 0, y: 0 });
  }

  function handleWheel(event: WheelEvent) {
    if (!event.ctrlKey && !event.metaKey) return;
    event.preventDefault();
    setScale((current) => clampScale(current - event.deltaY * 0.001));
  }

  function handleMouseDown(event: MouseEvent) {
    dragState.current = {
      startX: event.clientX,
      startY: event.clientY,
      originX: offset.x,
      originY: offset.y,
    };
  }

  function handleMouseMove(event: MouseEvent) {
    if (!dragState.current) return;
    const dx = event.clientX - dragState.current.startX;
    const dy = event.clientY - dragState.current.startY;
    setOffset({ x: dragState.current.originX + dx, y: dragState.current.originY + dy });
  }

  function handleMouseUp() {
    dragState.current = null;
  }

  return {
    scale,
    offset,
    zoomIn,
    zoomOut,
    reset,
    canZoomIn: scale < MAX_SCALE,
    canZoomOut: scale > MIN_SCALE,
    dragHandlers: {
      onWheel: handleWheel,
      onMouseDown: handleMouseDown,
      onMouseMove: handleMouseMove,
      onMouseUp: handleMouseUp,
      onMouseLeave: handleMouseUp,
    },
  };
}
