import * as React from 'react'

// Options
import { ERCToken } from '../../../constants/types'
import { hexToNumber } from '../../../utils/format-balances'

// Styled Components
import {
  StyledWrapper,
  AssetBalanceText,
  AssetName,
  BalanceColumn,
  FiatBalanceText,
  NameAndIcon,
  AssetIcon
} from './style'
import { formatWithCommasAndDecimals } from '../../../utils/format-prices'
import { withPlaceholderIcon } from '../../shared'

export interface Props {
  action?: () => void
  assetBalance: string
  fiatBalance: string
  token: ERCToken
}

const PortfolioAssetItem = (props: Props) => {
  const { assetBalance, fiatBalance, action, token } = props

  const AssetIconWithPlaceholder = React.useMemo(() => {
    return withPlaceholderIcon(AssetIcon, { size: 'big', marginLeft: 0, marginRight: 8 })
  }, [])

  return (
    <>
      {token.visible &&
        // Selecting a erc721 token is temp disabled until UI is ready for viewing NFT's
        <StyledWrapper disabled={token.isErc721} onClick={action}>
          <NameAndIcon>
            <AssetIconWithPlaceholder selectedAsset={token} />
            <AssetName>{token.name} {token.isErc721 ? hexToNumber(token.tokenId ?? '') : ''}</AssetName>
          </NameAndIcon>
          <BalanceColumn>
            {!token.isErc721 &&
              <FiatBalanceText>${formatWithCommasAndDecimals(fiatBalance)}</FiatBalanceText>
            }
            <AssetBalanceText>{token.isErc721 ? assetBalance : formatWithCommasAndDecimals(assetBalance)} {token.symbol}</AssetBalanceText>
          </BalanceColumn>
        </StyledWrapper>
      }
    </>
  )
}

export default PortfolioAssetItem
