import styled, { css, keyframes } from 'styled-components'
import { Size, Brand } from './index'

interface Props {
  isActive: boolean
  size?: Size
  brand?: Brand
}

const moveBg = keyframes`
  0% {
    background-position: 0% 50%;
  }
  50% {
    background-position: 100% 50%;
  }
  100% {
    background-position: 0% 50%;
  }
`

function matchForSize(size: Size) {
  if (size === 'sm') {
    return css`
      --width: 48px;
      --height: 24px;
      --border-width: 2px;
      --knob-width: 16px;
      --knob-height: 16px;
      --knob-border-width: 2px;
    `
  }

  if (size === 'lg') {
    return css`
      --width: 96px;
      --height: 50px;
      --border-width: 3px;
      --knob-width: 40px;
      --knob-height: 40px;
      --knob-border-width: 2px;
    `
  }

  return css``
}

function matchForActiveBrandColor(brand?: Brand) {
  if (brand === 'vpn') {
    return css`
      --knob-color: white;
      --bg-color: linear-gradient(
          135deg,
          #381e85 0%,
          #6845d1 30%,
          #737ade 100%,
          #4d56d0 75%,
          #0e1bd1 100%
        );
    `
  }

  if (brand === 'shields') {
    return css`
      --knob-color: white;
      --bg-color: linear-gradient(
          305.95deg,
          #BF14A2 0%,
          #F73A1C 98.59%,
          #737ade 100%,
          #4d56d0 75%,
          #0e1bd1 100%
        );
    `
  }

  return css`
    --bg-color: #E1E2F6;
    --knob-color: ${p => p.theme.color.interactive05};
  `
}

export const ToggleBox = styled.button<Props>`
  --bg-color: ${(p) => p.theme.color.disabled};
  --border-color: transparent;
  --border-width: 2px;
  --animation-name: none;

  --width: 60px;
  --height: 30px;

  --knob-width: 24px;
  --knob-height: 24px;
  --knob-right: initial;
  --knob-left: initial;
  --knob-border-top: 1px;
  --knob-color: white;
  --knob-border-color: transparent;
  --knob-border-width: 1px;

  position: relative;
  display: inline-flex;
  width: var(--width);
  height: var(--height);
  border: var(--border-width) solid var(--border-color);
  border-radius: 50px;
  background: var(--bg-color);
  background-size: 400% 400%;
  animation: var(--animation-name) 5s ease infinite;

  ${p => p.isActive && css`
    --knob-left: initial;
    --knob-right: 2px;
    --animation-name: ${moveBg};
  `}

  ${p => !p.isActive && css`
      --knob-left: 2px;
      --knob-right: initial;
  `}

  ${p => p.size && matchForSize(p.size)}
  ${p => p.isActive && matchForActiveBrandColor(p.brand)}

  &:hover {
    --border-color: ${p => p.theme.color.interactive05};
  }

  &:focus {
    --border-color: ${p => p.theme.color.focusBorder};
  }

  &:disabled,
  [disabled] {
    --knob-color: ${p => p.theme.color.subtle};
    --knob-border-color: #D9D9EA;
    --bg-color: ${(p) => p.theme.color.disabled};
  }
`
export const Knob = styled.div`
  position: absolute;
  top: var(--knob-border-width);
  left: var(--knob-left);
  right: var(--knob-right);
  width: var(--knob-width);
  height: var(--knob-height);
  border-radius: 50%;
  background-color: var(--knob-color);
  border: var(--knob-border-width) solid var(--knob-border-color);
`
